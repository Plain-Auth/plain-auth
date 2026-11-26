package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

// workDirFlag registers -c and --cwd, the directory a command runs in.
// Relative paths, such as field files, --output and a SQLite AUTH_DSN, resolve
// inside it.
func workDirFlag(fs *flag.FlagSet) *string {
	dir := new(string)
	fs.StringVar(dir, "c", "", "Run in this directory")
	fs.StringVar(dir, "cwd", "", "Run in this directory")
	return dir
}

func enterDir(dir string) error {
	if dir == "" {
		return nil
	}
	if err := os.Chdir(dir); err != nil {
		return fmt.Errorf("cannot use the working directory: %w", err)
	}
	return nil
}

// yesFlag registers -y and --yes on one switch.
func yesFlag(fs *flag.FlagSet, usage string) *bool {
	yes := new(bool)
	fs.BoolVar(yes, "y", false, usage)
	fs.BoolVar(yes, "yes", false, usage)
	return yes
}

// writeSchema writes ddl to path, or to a timestamped .sql file inside path
// when it is a directory, creating missing parent directories. It replaces an
// existing file only when yes is set.
func writeSchema(path, ddl string, yes bool, now time.Time, out io.Writer) error {
	if info, err := os.Stat(path); err == nil && info.IsDir() {
		path = filepath.Join(path, now.UTC().Format("2006-01-02T15-04-05.000Z")+".sql")
	}
	if _, err := os.Stat(path); err == nil && !yes {
		return fmt.Errorf("%s already exists; pass --yes to replace it", path)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(path, []byte(ddl), 0o644); err != nil {
		return err
	}
	_, err := fmt.Fprintf(out, "Wrote the auth schema to %s.\n", path)
	return err
}
