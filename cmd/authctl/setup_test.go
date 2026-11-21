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
