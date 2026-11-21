package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	authn "github.com/FineStack/frost-auth"
	"github.com/FineStack/frost-auth/adapters/sqlstore"
)

func createAdmin(ctx context.Context, args []string, in io.Reader, out, errOut io.Writer) error {
	fs := flag.NewFlagSet("create-admin", flag.ContinueOnError)
	fs.SetOutput(errOut)
	dialect := fs.String("dialect", "", "Target database dialect (sqlite, postgres, mysql)")
	email := fs.String("email", "", "Administrator email")
	name := fs.String("name", "", "Administrator display name")
	readPassword := fs.Bool("password-stdin", false, "Read one password from standard input")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if fs.NArg() != 0 || *dialect == "" || *name == "" || *email == "" || !*readPassword {
		return errors.New("create-admin requires --dialect, --name, --email and --password-stdin")
	}
	dsn := os.Getenv("AUTH_DSN")
	if dsn == "" {
		return errors.New("set AUTH_DSN to the target database")
	}
	if file, ok := in.(*os.File); ok {
		info, err := file.Stat()
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeCharDevice != 0 {
			return errors.New("pipe the password from a secret manager or redirect a private file to standard input")
		}
	}
	// A 128-unit Unicode password fits within 512 bytes. Limit input before allocating it.
	buf, err := io.ReadAll(io.LimitReader(in, 515))
	if err != nil {
		return errors.New("could not read password from standard input")
	}
	defer clear(buf)
	if len(buf) > 514 {
		return errors.New("password input is too long")
	}
	password := strings.TrimSuffix(strings.TrimSuffix(string(buf), "\n"), "\r")
	if strings.ContainsAny(password, "\r\n") {
		return errors.New("provide exactly one password line")
	}
	store, err := sqlstore.OpenForAdminBootstrap(ctx, *dialect, dsn)
	if err != nil {
		return errors.New("cannot open the target admin database; check the dialect, AUTH_DSN and installed admin schema")
	}
	defer store.Close()
	user, err := authn.BootstrapAdmin(ctx, store, *name, *email, password)
	if errors.Is(err, authn.ErrEmailTaken) {
		return errors.New("an account already uses that email")
	}
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(out, "Created administrator", user.Email)
	return err
}
