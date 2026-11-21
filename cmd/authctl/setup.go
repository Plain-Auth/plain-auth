package main

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strings"

	"github.com/Stonewrit/stonewrit-auth/internal/configenv"
	"github.com/Stonewrit/stonewrit-auth/schema"
)

func generateSecret() string { var b [32]byte; rand.Read(b[:]); return hex.EncodeToString(b[:]) }

func initConfig(args []string, out, errOut io.Writer) error {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	fs.SetOutput(errOut)
	filename := fs.String("env-file", ".env", "Destination for a new environment file")
	public := fs.String("url", "http://127.0.0.1:3000", "Public HTTP(S) URL")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("unexpected positional argument")
	}
	if _, _, err := configenv.ServerEndpoint(*public, ""); err != nil {
		return fmt.Errorf("init: %w", err)
	}
	// The generated file is sourceable by a POSIX shell. Restrict the value
	// to URL characters that can be written safely as a single-quoted value.
	for _, r := range *public {
		if r == '\'' || r < ' ' || r == 127 {
			return errors.New("init: invalid character in public URL")
		}
	}
	temp, err := os.CreateTemp(filepath.Dir(*filename), ".auth-init-*")
	if err != nil {
		return err
	}
	defer os.Remove(temp.Name())
	if _, err = fmt.Fprintf(temp, "AUTH_SECRET=%s\nAUTH_URL='%s'\n", generateSecret(), *public); err != nil {
		temp.Close()
		return err
	}
	if err = temp.Close(); err != nil {
		return err
	}
	// Link only after all writes succeed. An existing config always wins.
	if err = os.Link(temp.Name(), *filename); err != nil {
		if errors.Is(err, os.ErrExist) {
			return errors.New("init: environment file already exists")
		}
		return err
	}
	_, err = fmt.Fprintf(out, "Created %s. Load it into the host environment before startup.\n", *filename)
	return err
}

func printInfo(out io.Writer) error {
	version := "development"
	if build, ok := debug.ReadBuildInfo(); ok && build.Main.Version != "" {
		version = build.Main.Version
	}
	_, err := fmt.Fprintf(out, "authctl %s\nGo %s (%s/%s)\nSQL dialects: sqlite, postgres, mysql\nSchema profiles: %s\n", version, runtime.Version(), runtime.GOOS, runtime.GOARCH, strings.Join(schema.Profiles(), ", "))
	return err
}
