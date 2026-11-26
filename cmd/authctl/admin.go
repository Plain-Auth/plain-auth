package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	authn "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/adapters/sqlstore"
	"github.com/Plain-Org/plain-auth/schema"
)

func createAdmin(ctx context.Context, args []string, in io.Reader, out, errOut io.Writer) error {
	for _, arg := range args {
		// A password on the command line would reach the shell history and
		// the process list, so there is no such flag; say so without echoing it.
		if name, _, _ := strings.Cut(strings.TrimLeft(arg, "-"), "="); strings.HasPrefix(arg, "-") && name == "password" {
			return errors.New("create-admin takes no password argument; pipe the password to --password-stdin")
		}
	}
	fs := flag.NewFlagSet("create-admin", flag.ContinueOnError)
	fs.SetOutput(errOut)
	dialect := fs.String("dialect", "", "Target database dialect (sqlite, postgres, mysql)")
	email := fs.String("email", "", "Administrator email")
	name := fs.String("name", "Admin", "Administrator display name")
	roles := fs.String("role", "admin", "Comma-separated roles to grant")
	data := fs.String("data", "", "JSON object with the image and additional user fields to set")
	userFile := schemaPathFlag(fs, "user-fields", "user fields")
	unverified := fs.Bool("no-email-verified", false, "Leave the email unverified")
	force := fs.Bool("force", false, "Create the administrator even when the database already has users")
	yes := yesFlag(fs, "Same as --force")
	readPassword := fs.Bool("password-stdin", false, "Read one password from standard input")
	dir := workDirFlag(fs)
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if err := enterDir(*dir); err != nil {
		return err
	}
	if fs.NArg() != 0 || *dialect == "" || *email == "" || !*readPassword {
		return errors.New("create-admin requires --dialect, --email and --password-stdin")
	}
	bootstrap := authn.AdminBootstrap{Name: *name, Email: *email, EmailVerified: !*unverified}
	for role := range strings.SplitSeq(*roles, ",") {
		bootstrap.Roles = append(bootstrap.Roles, strings.TrimSpace(role))
	}
	var err error
	if bootstrap.UserFields, err = loadSchemaFile(*userFile, "user fields", schema.ReadUserFields); err != nil {
		return err
	}
	if bootstrap.Image, bootstrap.Values, err = adminData(*data); err != nil {
		return err
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
	bootstrap.Password = password
	store, err := sqlstore.OpenForAdminBootstrap(ctx, *dialect, dsn)
	if err != nil {
		return errors.New("cannot open the target admin database; check the dialect, AUTH_DSN and installed admin schema")
	}
	defer store.Close()
	users, err := store.CountUsers(ctx)
	if err != nil {
		return errors.New("cannot count the existing users; check AUTH_DSN and apply the schema first")
	}
	if users > 0 && !*force && !*yes {
		return fmt.Errorf("found %d existing user(s); pass --force or --yes to create an administrator anyway", users)
	}
	user, err := authn.BootstrapAdminAccount(ctx, store, bootstrap)
	if errors.Is(err, authn.ErrEmailTaken) {
		return errors.New("an account already uses that email")
	}
	if errors.Is(err, authn.ErrAdminExists) {
		return fmt.Errorf("%w (roles %s); grant further roles through the admin API", err, strings.Join(bootstrap.Roles, ","))
	}
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(out, "Admin user created successfully.\nUser ID: %s\nEmail: %s\nRole: %s\n", user.ID, user.Email, user.Role)
	return err
}

// adminData reads --data: an image, which must be a string or null, and the
// values of declared additional user fields. The name, email, role and
// emailVerified keys are ignored, because their own flags decide them.
func adminData(data string) (*string, map[string]any, error) {
	if data == "" {
		return nil, nil, nil
	}
	dec := json.NewDecoder(strings.NewReader(data))
	dec.UseNumber()
	var values map[string]any
	if err := dec.Decode(&values); err != nil {
		var syntax *json.SyntaxError
		if errors.As(err, &syntax) || errors.Is(err, io.ErrUnexpectedEOF) {
			return nil, nil, errors.New("--data must be valid JSON")
		}
		return nil, nil, errors.New("--data must be a JSON object")
	}
	if values == nil {
		return nil, nil, errors.New("--data must be a JSON object")
	}
	if dec.Decode(new(any)) != io.EOF {
		return nil, nil, errors.New("--data must be valid JSON")
	}
	var image *string
	if raw, ok := values["image"]; ok {
		switch v := raw.(type) {
		case string:
			image = &v
		case nil:
		default:
			return nil, nil, errors.New("--data: image must be a string or null")
		}
	}
	for _, key := range []string{"image", "name", "email", "role", "emailVerified"} {
		delete(values, key)
	}
	return image, values, nil
}
