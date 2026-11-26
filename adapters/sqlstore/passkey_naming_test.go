package sqlstore

import (
	"testing"

	auth "github.com/Plain-Org/plain-auth"
	pk "github.com/Plain-Org/plain-auth/plugins/passkey"
	"github.com/google/uuid"
)

// Registration stores each authenticator's AAGUID, passes it to the
// callback and returns it from the list; the callback can label a key from
// it while a client-supplied name wins, and a label resolves when reading.
func TestPasskeyAuthenticatorNamesAcrossEngines(t *testing.T) {
	const (
		google    = "ea9b8d66-4d01-1d21-3ce4-b6b48cb575d4"
		onePass   = "bada5566-a7aa-401f-bd96-45619a55120d"
		bitwarden = "d548826e-79b4-db40-a3d8-11116f7e8349"
		zero      = "00000000-0000-0000-0000-000000000000"
	)
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			seen := make(chan string, 8)
			label := false
			p := newPasskeyPeers(t, dialect, pk.Options{Registration: pk.RegistrationOptions{AfterVerification: func(_ auth.EndpointContext, proof pk.VerifiedRegistration) (pk.RegistrationDecision, error) {
				seen <- proof.AAGUID
				if !label {
					return pk.RegistrationDecision{}, nil
				}
				return pk.RegistrationDecision{Name: pk.AuthenticatorName(proof.AAGUID)}, nil
			}}}, auth.Options{})
			enroll := func(aaguid, name string) map[string]any {
				t.Helper()
				options, set := p.call(t, p.first, "generate-register-options", nil, 200, p.session)
				key := newSoftwareKey(t)
				if aaguid != zero {
					id := uuid.MustParse(aaguid)
					key.aaguid = id[:]
				}
				key.handle = options["user"].(map[string]any)["id"].(string)
				body := map[string]any{"response": key.response(t, options["challenge"].(string), passkeyPeerOrigin, "example.test", 0, true)}
				if name != "" {
					body["name"] = name
				}
				row, _ := p.call(t, p.second, "verify-registration", body, 200, set[0], p.session)
				select {
				case got := <-seen:
					if got != aaguid || row["aaguid"] != aaguid {
						t.Fatal("the authenticator's AAGUID was not stored and passed to the callback", got, row["aaguid"])
					}
				default:
					t.Fatal("the registration callback never ran")
				}
				return row
			}
			unlabeled := enroll(google, "")
			label = true
			rows := []map[string]any{unlabeled, enroll(google, ""), enroll(onePass, "   "), enroll(bitwarden, "  Work key  "), enroll(zero, "")}
			for i, want := range []any{nil, "Google Password Manager", "1Password", "Work key", nil} {
				if rows[i]["name"] != want {
					t.Fatalf("passkey %d was named %v, want %v", i, rows[i]["name"], want)
				}
			}
			listed, _ := p.call(t, p.first, "list-user-passkeys", nil, 200, p.session)
			byID := map[any]map[string]any{}
			for _, item := range listed["items"].([]any) {
				row := item.(map[string]any)
				byID[row["id"]] = row
			}
			for _, want := range rows {
				got := byID[want["id"]]
				if len(byID) != 5 || got == nil || got["aaguid"] != want["aaguid"] || got["name"] != want["name"] {
					t.Fatalf("the passkey list returned %v, want %v", got, want)
				}
			}
			display := func(row map[string]any) string {
				if name, ok := row["name"].(string); ok {
					return name
				}
				if name := pk.AuthenticatorName(row["aaguid"].(string)); name != "" {
					return name
				}
				return "Passkey"
			}
			if display(byID[unlabeled["id"]]) != "Google Password Manager" || display(byID[rows[4]["id"]]) != "Passkey" {
				t.Fatal("a passkey label did not resolve from its authenticator when reading")
			}
		})
	}
}
