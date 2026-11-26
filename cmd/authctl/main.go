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
	"time"

	"github.com/Plain-Org/plain-auth/adapters/sqlstore"
	"github.com/Plain-Org/plain-auth/schema"
)

const usage = `Usage: authctl <command>

  init      [--env-file .env] [--url URL]       Write a new local configuration
  info      [--json] [--copy]                  Show runtime and driver details
  check [schema] --dialect sqlite|postgres|mysql  Check target columns without writing to the database
  generate  --dialect sqlite|postgres|mysql [--output PATH [--yes]]
                                               Write the auth schema to stdout or a file
  migrate   --dialect sqlite|postgres|mysql     Apply the schema to AUTH_DSN
  create-admin --dialect D --name N --email E --password-stdin
                                               Create the first administrator in AUTH_DSN
  secret                                       Print a new signing secret

  init, check, generate, migrate and create-admin accept -c/--cwd DIR to run in DIR.

  check, generate and migrate accept --plugins with comma-separated schema profiles.
  check, generate and migrate accept --user-fields FILE, --session-fields FILE, --account-fields FILE and --organization-role-fields FILE with JSON field definitions.
  With the siwe plugin, --wallet-schema FILE selects the physical wallet table and columns.
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
		return printInfo(args[1:], out, errOut)
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
		userFile := schemaPathFlag(fs, "user-fields", "user fields")
		sessionFile := schemaPathFlag(fs, "session-fields", "session fields")
		accountFile := schemaPathFlag(fs, "account-fields", "account fields")
		roleFile := schemaPathFlag(fs, "organization-role-fields", "organization role fields")
		walletFile := schemaPathFlag(fs, "wallet-schema", "wallet schema")
		dir := workDirFlag(fs)
		var output string
		var yes *bool
		var asJSON, prepareKeyLedger bool
		if args[0] == "check" {
			fs.BoolVar(&asJSON, "json", false, "Write findings as a JSON array")
		}
		if args[0] == "migrate" {
			fs.BoolVar(&prepareKeyLedger, "api-key-ledger", false, "Install the API-key schema and backfill its permanent digest ledger")
			// migrate never asks before applying; the switch is accepted for scripts.
			yes = yesFlag(fs, "Apply without confirmation (migrate never asks)")
		}
		if args[0] == "generate" {
			fs.StringVar(&output, "output", "", "Write the schema to this file, or to a timestamped .sql file in this directory")
			yes = yesFlag(fs, "Replace an existing --output file")
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
		if err := enterDir(*dir); err != nil {
			return err
		}
		var profiles []string
		if *pluginNames != "" {
			for name := range strings.SplitSeq(*pluginNames, ",") {
				profiles = append(profiles, strings.TrimSpace(name))
			}
		}
		users, err := loadSchemaFile(*userFile, "user fields", schema.ReadUserFields)
		if err != nil {
			return err
		}
		sessions, err := loadSchemaFile(*sessionFile, "session fields", schema.ReadSessionFields)
		if err != nil {
			return err
		}
		wallet, err := loadSchemaFile(*walletFile, "wallet schema", schema.ReadWalletSchema)
		if err != nil {
			return err
		}
		accounts, err := loadSchemaFile(*accountFile, "account fields", schema.ReadAccountFields)
		if err != nil {
			return err
		}
		roles, err := loadSchemaFile(*roleFile, "organization role fields", schema.ReadRoleFields)
		if err != nil {
			return err
		}
		options := schema.Options{AdditionalFields: schema.AdditionalFields{User: users, Session: sessions, Account: accounts, OrganizationRole: roles}, Wallet: wallet}
		if args[0] == "check" {
			return checkDatabase(ctx, *dialect, profiles, options, asJSON, out)
		}
		if prepareKeyLedger {
			profiles = append(profiles, "api-key")
		}
		ddl, err := schema.GenerateWithOptions(*dialect, profiles, options)
		if err != nil {
			return err
		}
		if args[0] == "generate" {
			if output != "" {
				return writeSchema(output, ddl, *yes, time.Now(), out)
			}
			_, err = io.WriteString(out, ddl)
			return err
		}
		dsn := os.Getenv("AUTH_DSN")
		if dsn == "" {
			return errors.New("set AUTH_DSN to the target database")
		}
		var store *sqlstore.Store
		if len(users)+len(sessions)+len(accounts)+len(roles) > 0 || *walletFile != "" {
			store, err = sqlstore.OpenWithOptions(ctx, *dialect, dsn, profiles, options)
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

func schemaPathFlag(fs *flag.FlagSet, name, description string) *string {
	var file string
	fs.Func(name, "Read "+description+" from a JSON file", func(value string) error {
		if value == "" {
			return fmt.Errorf("a %s file is required", description)
		}
		file = value
		return nil
	})
	return &file
}

func loadSchemaFile[T any](path, description string, parse func(io.Reader) (T, error)) (T, error) {
	var zero T
	if path == "" {
		return zero, nil
	}
	file, err := os.Open(path)
	if err != nil {
		return zero, fmt.Errorf("read %s: %w", description, err)
	}
	value, err := parse(file)
	if err = errors.Join(err, file.Close()); err != nil {
		return zero, fmt.Errorf("read %s: %w", description, err)
	}
	return value, nil
}
