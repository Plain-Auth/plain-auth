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

	"github.com/nabuhadba/go-better-auth/adapters/sqlstore"
	"github.com/nabuhadba/go-better-auth/schema"
)

const usage = `Usage: authctl <command>

  init      [--env-file .env] [--url URL]       Write a new local configuration
  info                                         Show runtime and driver details
  generate  --dialect sqlite|postgres|mysql     Write the auth schema to stdout
  migrate   --dialect sqlite|postgres|mysql     Apply the schema to AUTH_DSN
  secret                                       Print a new signing secret

  generate and migrate accept --plugins with comma-separated schema profiles.
`

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()
	if err := run(ctx, os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string, out, errOut io.Writer) error {
	if len(args) == 0 || args[0] == "--help" || args[0] == "-h" || args[0] == "help" {
		_, err := io.WriteString(out, usage)
		return err
	}
	switch args[0] {
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
	case "generate", "migrate":
		fs := flag.NewFlagSet(args[0], flag.ContinueOnError)
		fs.SetOutput(errOut)
		dialect := fs.String("dialect", "", "Database dialect (sqlite, postgres, mysql)")
		pluginNames := fs.String("plugins", "", "Comma-separated schema profiles (organization, organization-teams, rate-limit, stripe-subscriptions, two-factor)")
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
		ddl, err := schema.Generate(*dialect, profiles)
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
		store, err := sqlstore.OpenWithSchema(ctx, *dialect, dsn, ddl)
		if err != nil {
			return fmt.Errorf("migrate: %w", err)
		}
		if err = store.Close(); err != nil {
			return err
		}
		_, err = fmt.Fprintf(out, "Applied auth schema (%s).\n", *dialect)
		return err
	default:
		return fmt.Errorf("unknown command %q\n%s", args[0], usage)
	}
}
