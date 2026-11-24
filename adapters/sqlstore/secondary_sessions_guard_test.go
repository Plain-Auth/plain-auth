package sqlstore

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The session mirror relies on single write paths: one session insert, one
// session delete and one user delete, every change to a user column a
// session copy holds going through execUserUpdate, and every other session
// update either touching only organization selection or deleting the copy.
// A new statement that bypasses them would leave stale copies, so this
// test fails until it is routed or listed here.
func TestSessionMirrorWritePaths(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	// User updates that change only columns a session copy does not hold.
	exempt := []string{`"lastLoginMethod"=?`, `"twoFactorEnabled"=false`, `SET "phoneNumber"=?,"phoneNumberVerified"=? WHERE`}
	counts := map[string]int{}
	for _, file := range files {
		if strings.HasSuffix(file, "_test.go") {
			continue
		}
		raw, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		lines := strings.Split(string(raw), "\n")
		for i, line := range lines {
			for _, statement := range []string{`INSERT INTO "session"`, `DELETE FROM "session"`, `DELETE FROM "user"`} {
				if strings.Contains(line, statement) {
					counts[statement]++
				}
			}
			if strings.Contains(line, `UPDATE "session"`) {
				selection := strings.Contains(line, `"activeOrganizationId"`) || strings.Contains(line, `"activeTeamId"`)
				later := strings.Join(lines[i:min(i+25, len(lines))], "\n")
				if !selection && !strings.Contains(later, "sessionMirror().forget(") {
					t.Errorf("%s:%d updates a session without deleting its copy", file, i+1)
				}
			}
			if !strings.Contains(line, `UPDATE "user"`) {
				continue
			}
			window := strings.Join(lines[i:min(i+3, len(lines))], "\n")
			routed := strings.Contains(window, "execUserUpdate(")
			for _, column := range exempt {
				routed = routed || strings.Contains(line, column)
			}
			if !routed {
				t.Errorf("%s:%d updates the user without execUserUpdate", file, i+1)
			}
		}
	}
	for statement, want := range map[string]int{`INSERT INTO "session"`: 1, `DELETE FROM "session"`: 1, `DELETE FROM "user"`: 1} {
		if counts[statement] != want {
			t.Errorf("%d statements %s, want %d", counts[statement], statement, want)
		}
	}
}
