package main

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInitializeEnvironment(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".env")
	var out bytes.Buffer
	args := []string{"init", "--env-file", path, "--url", "https://service.example/login"}
	if err := run(context.Background(), args, &out, io.Discard); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	first, second, _ := strings.Cut(string(data), "\n")
	if len(strings.TrimPrefix(first, "AUTH_SECRET=")) != 64 || second != "AUTH_URL='https://service.example/login'\n" {
		t.Fatal("invalid env file")
	}
	if strings.Contains(out.String(), first) {
		t.Fatal("init printed signing secret")
	}
	if err := run(context.Background(), args, &out, io.Discard); err == nil {
		t.Fatal("replaced existing file")
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(data, after) {
		t.Fatal("existing file changed")
	}
}

func TestInitRejectsUnusablePublicURL(t *testing.T) {
	for _, public := range []string{
		"https://service.example/a/../login", "https://service.example/a//login",
		"https://service.example/embedded space", "https://service.example/a%2Fb",
		"https://service.example/login?", "https://service.example/#",
		"https://user@service.example/login", "file:///login", "/relative",
		"https://service.example/it's", "https://service.example/line\nbreak",
	} {
		t.Run(public, func(t *testing.T) {
			dest := filepath.Join(t.TempDir(), ".env")
			err := run(context.Background(), []string{"init", "--url", public, "--env-file", dest}, io.Discard, io.Discard)
			if err == nil {
				t.Fatal("accepted unusable environment URL")
			}
			if _, err := os.Stat(dest); !os.IsNotExist(err) {
				t.Fatal("wrote an unusable configuration")
			}
		})
	}
}
