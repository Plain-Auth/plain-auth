// Command authctl manages a host application's auth schema and secrets.
package main

import (
	"context"

	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"

	"github.com/Plain-Auth/plain-auth/adapters/sqlstore"
	"github.com/Plain-Auth/plain-auth/schema"
)

const usage = `Usage: authctl <command>

  init      [--env-file .env] [--url URL]       Write a new local configuration
  info                                         Show runtime and driver details
  check [schema] --dialect sqlite|postgres|mysql  Check target columns without writing to the database
  generate  --dialect sqlite|postgres|mysql     Write the auth schema to stdout
  migrate   --dialect sqlite|postgres|mysql     Apply the schema to AUTH_DSN
  create-admin --dialect D --name N --email E --password-stdin
                                               Create the first administrator in AUTH_DSN
  secret                                       Print a new signing secret

  check, generate and migrate accept --plugins with comma-separated schema profiles.
  check, generate and migrate accept --user-fields FILE and --session-fields FILE with JSON field definitions.
  migrate --api-key-ledger includes the API-key schema and reserves existing key digests.
`

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()
	if err := run(ctx, os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(failureCode(os.Args[1:], err))
	}
}

func run(ctx context.Context, args []string, out, errOut io.Writer) error {
	if len(args) == 0 || args[0] == "--help" || args[0] == "-h" || args[0] == "help" {
		_, err := io.WriteString(out, usage)
		return err
	}
	switch args[0] {
	case "create-admin":
		return createAdmin(ctx, args[1:], os.Stdin, out, errOut)
	case "init":
		return initConfig(args[1:], out, errOut)
	case "info":
		if len(args) != 1 {
			return errors.New("info takes no arguments")
		}
		return printInfo(out)
	case "secret":
		if len(args) != 1 {
			return errors.New("secret takes no arguments")
		}

		fmt.Fprintln(errOut, "Add the following to your .env file:")
		_, err := fmt.Fprintf(out, "AUTH_SECRET=%s\n", generateSecret())
		return err
	case "generate", "migrate", "check":
		if args[0] == "check" && len(args) > 1 && args[1] == "schema" {
			args = append([]string{"check"}, args[2:]...)
		}
		fs := flag.NewFlagSet(args[0], flag.ContinueOnError)
		fs.SetOutput(errOut)
		dialect := fs.String("dialect", "", "Database dialect (sqlite, postgres, mysql)")
		pluginNames := fs.String("plugins", "", "Comma-separated schema profiles ("+strings.Join(schema.Profiles(), ", ")+")")
		userFile := fieldPathFlag(fs, "user")
		sessionFile := fieldPathFlag(fs, "session")
		var asJSON, prepareKeyLedger bool
		if args[0] == "check" {
			fs.BoolVar(&asJSON, "json", false, "Write findings as a JSON array")
		}
		if args[0] == "migrate" {
			fs.BoolVar(&prepareKeyLedger, "api-key-ledger", false, "Install the API-key schema and backfill its permanent digest ledger")
		}
		if err := fs.Parse(args[1:]); err != nil {
			if errors.Is(err, flag.ErrHelp) {
				return nil
			}
			return err
		}
		if fs.NArg() != 0 {
			return errors.New("unexpected positional argument")
		}
		var profiles []string
		if *pluginNames != "" {
			for name := range strings.SplitSeq(*pluginNames, ",") {
				profiles = append(profiles, strings.TrimSpace(name))
			}
		}
		users, err := loadFieldFile(*userFile, "user", schema.ReadUserFields)
		if err != nil {
			return err
		}
		sessions, err := loadFieldFile(*sessionFile, "session", schema.ReadSessionFields)
		if err != nil {
			return err
		}
		fields := schema.AdditionalFields{User: users, Session: sessions}
		if args[0] == "check" {
			return checkDatabase(ctx, *dialect, profiles, fields, asJSON, out)
		}
		if prepareKeyLedger {
			profiles = append(profiles, "api-key")
		}
		ddl, err := schema.GenerateWithAdditionalFields(*dialect, profiles, fields)
		if err != nil {
			return err
		}
		if args[0] == "generate" {
			_, err = io.WriteString(out, ddl)
			return err
		}
		dsn := os.Getenv("AUTH_DSN")
		if dsn == "" {
			return errors.New("set AUTH_DSN to the target database")
		}
		var store *sqlstore.Store
		if len(fields.User)+len(fields.Session) > 0 {
			store, err = sqlstore.OpenWithAdditionalFields(ctx, *dialect, dsn, profiles, fields)
		} else {
			store, err = sqlstore.OpenWithSchema(ctx, *dialect, dsn, ddl)
		}
		if err != nil {
			return fmt.Errorf("migrate: %w", err)
		}
		if prepareKeyLedger {
			err = store.PrepareAPIKeyLedger(ctx)
		}
		if err = errors.Join(err, store.Close()); err != nil {
			return err
		}
		_, err = fmt.Fprintf(out, "Applied auth schema (%s).\n", *dialect)
		return err
	default:
		return fmt.Errorf("unknown command %q\n%s", args[0], usage)
	}
}

func fieldPathFlag(fs *flag.FlagSet, model string) *string {
	var file string
	fs.Func(model+"-fields", "Read additional "+model+" fields from a JSON file", func(value string) error {
		if value == "" {
			return fmt.Errorf("a %s fields file is required", model)
		}
		file = value
		return nil
	})
	return &file
}

func loadFieldFile[T any](path, model string, parse func(io.Reader) (map[string]T, error)) (map[string]T, error) {
	if path == "" {
		return nil, nil
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("read %s fields: %w", model, err)
	}
	fields, err := parse(file)
	if err = errors.Join(err, file.Close()); err != nil {
		return nil, fmt.Errorf("read %s fields: %w", model, err)
	}
	return fields, nil
}
