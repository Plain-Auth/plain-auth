// Command schemafixture batches independent differential tests over a JSON-lines stream.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/Stonewrit/stonewrit-auth/adapters/sqlstore"
	"github.com/Stonewrit/stonewrit-auth/schema"
)

type request struct {
	Dialect, Path string
	Profiles      []string
}

func run(in request) (string, error) {
	ddl, err := schema.Generate(in.Dialect, in.Profiles)
	if err != nil || in.Path == "" {
		return ddl, err
	}
	if in.Dialect != "sqlite" || !filepath.IsLocal(in.Path) {
		return "", fmt.Errorf("fixture database must be a local SQLite filename")
	}
	for range 2 {
		s, err := sqlstore.OpenWithSchema(context.Background(), in.Dialect, in.Path, ddl)
		if err != nil {
			return "", err
		}
		if err = s.Close(); err != nil {
			return "", err
		}
	}
	return "", nil
}

func main() {
	lines := bufio.NewScanner(os.Stdin)
	out := json.NewEncoder(os.Stdout)
	for lines.Scan() {
		var in request
		if err := json.Unmarshal(lines.Bytes(), &in); err != nil {
			panic(err)
		}
		value, err := run(in)
		if err != nil {
			panic(err)
		}
		if err := out.Encode(value); err != nil {
			panic(err)
		}
	}
	if err := lines.Err(); err != nil {
		panic(err)
	}
}
