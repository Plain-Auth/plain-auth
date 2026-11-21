package schema_test

import (
	"slices"
	"strings"
	"testing"

	"github.com/nabuhadba/go-better-auth/schema"
)

func TestGeneratePluginSelection(t *testing.T) {
	profiles := []string{"two-factor", "organization-teams", "stripe-subscriptions"}
	original := slices.Clone(profiles)
	got, err := schema.Generate("sqlite", profiles)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(profiles, original) {
		t.Fatal("caller-owned selection was modified")
	}
	for _, item := range []string{`"activeTeamId" text`, `"stripeCustomerId" text`, `create table "twoFactor"`, `create table "subscription"`, `create index "teamMember_userId_idx"`} {
		if !strings.Contains(got, item) {
			t.Fatalf("missing %s", item)
		}
	}
	repeated, err := schema.Generate("sqlite3", append(slices.Clone(profiles), "two-factor"))
	if err != nil || repeated != got {
		t.Fatal("repeating a profile changed the DDL", err)
	}
	for _, invalid := range [][]string{{""}, {"unsupported"}, {"organization", "organization-teams"}, {"organization,two-factor"}} {
		if _, err := schema.Generate("sqlite", invalid); err == nil {
			t.Fatalf("accepted %q", invalid)
		}
	}
	if _, err := schema.Generate("unknown", nil); err == nil {
		t.Fatal("accepted unknown dialect")
	}
}
