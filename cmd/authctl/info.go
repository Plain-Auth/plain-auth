package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os/exec"
	"runtime"
	"runtime/debug"
	"strings"

	"github.com/Plain-Org/plain-auth/schema"
)

const modulePath = "github.com/Plain-Org/plain-auth"

type infoReport struct {
	Authctl struct {
		Version string `json:"version"`
	} `json:"authctl"`
	Go struct {
		Version string `json:"version"`
	} `json:"go"`
	System struct {
		Platform string `json:"platform"`
		Arch     string `json:"arch"`
		CPUCount int    `json:"cpuCount"`
	} `json:"system"`
	Databases      []infoDatabase `json:"databases"`
	SchemaProfiles []string       `json:"schemaProfiles"`
}

type infoDatabase struct {
	Dialect string `json:"dialect"`
	Driver  string `json:"driver"`
	Version string `json:"version"`
}

// printInfo reports authctl's version, the Go runtime, the platform, the SQL
// drivers it was built with and the schema profiles. It prints no
// environment values.
func printInfo(args []string, out, errOut io.Writer) error {
	fs := flag.NewFlagSet("info", flag.ContinueOnError)
	fs.SetOutput(errOut)
	var asJSON, copyReport bool
	fs.BoolVar(&asJSON, "j", false, "Print the report as JSON")
	fs.BoolVar(&asJSON, "json", false, "Print the report as JSON")
	fs.BoolVar(&copyReport, "c", false, "Copy the report to the clipboard")
	fs.BoolVar(&copyReport, "copy", false, "Copy the report to the clipboard")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("info takes no positional arguments")
	}
	build, _ := debug.ReadBuildInfo()
	r := collectInfo(build)
	var report bytes.Buffer
	if asJSON {
		enc := json.NewEncoder(&report)
		enc.SetIndent("", "  ")
		if err := enc.Encode(r); err != nil {
			return err
		}
	} else {
		drivers := make([]string, len(r.Databases))
		for i, d := range r.Databases {
			drivers[i] = d.Dialect + " (" + d.Driver + " " + d.Version + ")"
		}
		fmt.Fprintf(&report, "authctl %s\nGo %s (%s/%s, %d CPUs)\nSQL dialects: %s\nSchema profiles: %s\n",
			r.Authctl.Version, r.Go.Version, r.System.Platform, r.System.Arch, r.System.CPUCount, strings.Join(drivers, ", "), strings.Join(r.SchemaProfiles, ", "))
	}
	if _, err := out.Write(report.Bytes()); err != nil {
		return err
	}
	if copyReport {
		copyToClipboard(report.Bytes(), errOut)
	}
	return nil
}

// collectInfo builds the report from build, which may be nil.
func collectInfo(build *debug.BuildInfo) infoReport {
	var r infoReport
	r.Authctl.Version = "development"
	r.Go.Version = runtime.Version()
	r.System.Platform, r.System.Arch, r.System.CPUCount = runtime.GOOS, runtime.GOARCH, runtime.NumCPU()
	r.SchemaProfiles = schema.Profiles()
	versions := map[string]string{}
	if build != nil {
		// Built as a tool of a host module, the main module is the host's,
		// so the version comes from the dependency entry.
		if build.Main.Path == modulePath {
			versions[modulePath] = build.Main.Version
		}
		// A replaced module keeps its own path, with the replacement's
		// version: "(devel)" for a directory.
		for _, d := range build.Deps {
			v := d.Version
			if d.Replace != nil {
				v = d.Replace.Version
				if v == "" {
					v = "(devel)"
				}
			}
			versions[d.Path] = v
		}
		if v := versions[modulePath]; v != "" && v != "(devel)" {
			r.Authctl.Version = v
		}
	}
	for _, d := range []infoDatabase{
		{Dialect: "sqlite", Driver: "github.com/mattn/go-sqlite3"},
		{Dialect: "postgres", Driver: "github.com/jackc/pgx/v5"},
		{Dialect: "mysql", Driver: "github.com/go-sql-driver/mysql"},
	} {
		d.Version = versions[d.Driver]
		if d.Version == "" {
			d.Version = "unknown"
		}
		r.Databases = append(r.Databases, d)
	}
	return r
}

// copyToClipboard hands the report to the platform's clipboard command and
// says on errOut whether it worked; other platforms are left alone.
func copyToClipboard(report []byte, errOut io.Writer) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("pbcopy")
	case "linux":
		cmd = exec.Command("xclip", "-selection", "clipboard")
	case "windows":
		cmd = exec.Command("clip")
	default:
		return
	}
	cmd.Stdin = bytes.NewReader(report)
	if cmd.Run() != nil {
		fmt.Fprintln(errOut, "Could not copy to clipboard")
		return
	}
	fmt.Fprintln(errOut, "Copied to clipboard")
}
