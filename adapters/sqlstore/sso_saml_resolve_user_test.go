package sqlstore

import (
	"context"
	"reflect"
	"sync"
	"testing"
	"time"

	auth "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/plugins/sso"
	"github.com/crewjam/saml"
)

// SAML sign-ins call ResolveUser with the IdP entity ID and NameID as the
// account key and the verified attributes as claims.
func TestEnterpriseSAMLResolveUser(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			ctx := t.Context()
			p := newSAMLPolicy(t, dialect)
			p.directory("acme", nil)
			now := time.Now().UTC()
			if err := p.store.CreateUser(ctx, auth.User{ID: "selected", Name: "Provisioned Employee", Email: "provisioned@example.test", CreatedAt: now, UpdatedAt: now}, "credential", nil); err != nil {
				t.Fatal(err)
			}
			var mu sync.Mutex
			var inputs []sso.UserResolutionInput
			var readErr error
			decision := sso.UserResolution{Action: sso.ResolveLink, UserID: "selected", Profile: "preserve"}
			resolve := func(rc context.Context, in sso.UserResolutionInput) (sso.UserResolution, error) {
				read, cancel := context.WithTimeout(rc, 2*time.Second)
				defer cancel()
				_, e := p.store.FindAccountUser(read, "provisioned@example.test")
				mu.Lock()
				defer mu.Unlock()
				inputs, readErr = append(inputs, in), e
				return decision, nil
			}
			var provisioned []sso.Provisioning
			provision := func(_ context.Context, pr sso.Provisioning) error {
				mu.Lock()
				defer mu.Unlock()
				provisioned = append(provisioned, pr)
				return nil
			}
			h := p.pluginHost(sso.Options{SAML: &sso.SAMLOptions{}, ResolveUser: resolve, ProvisionUser: provision, ProvisionUserOnEveryLogin: true}, nil)
			assert := func(nameID string) func(*saml.Assertion) {
				return func(a *saml.Assertion) {
					a.Subject.NameID.Value = nameID
					a.AttributeStatements[0].Attributes = append(a.AttributeStatements[0].Attributes,
						saml.Attribute{Name: "displayName", Values: []saml.AttributeValue{{Value: "Local Employee"}}},
						saml.Attribute{Name: "groups", Values: []saml.AttributeValue{{Value: "staff"}, {Value: "admins"}}})
					for i, attr := range a.AttributeStatements[0].Attributes {
						if attr.Name == "email" {
							a.AttributeStatements[0].Attributes[i].Values = []saml.AttributeValue{{Value: "Employee@acme.example"}}
						}
					}
				}
			}
			sessions := func() int {
				var n int
				if err := p.store.db.QueryRowContext(ctx, p.store.bind(`SELECT COUNT(*) FROM "session"`)).Scan(&n); err != nil {
					t.Fatal(err)
				}
				return n
			}

			req, state := p.start(h, "acme")
			location, session := samlOutcome(t, p.finish(h, "acme", req, state, nil, assert("employee"), nil))
			if location.String() != "https://service.test/home" || !session {
				t.Fatal("a SAML resolver link did not finish the sign-in", location)
			}
			mu.Lock()
			in, e := inputs[len(inputs)-1], readErr
			mu.Unlock()
			if e != nil {
				t.Fatal("the SAML resolver ran inside the sign-in transaction", e)
			}
			if in.Protocol != "saml" || in.ProviderID != "acme" {
				t.Fatal("the SAML resolver input named the wrong protocol or provider", in.Protocol, in.ProviderID)
			}
			if in.AccountKey.Issuer != samlPolicyIdP+"/metadata" {
				t.Fatal("the SAML account key issuer was not the IdP entity ID", in.AccountKey)
			}
			if in.AccountKey.AccountID != "employee" {
				t.Fatal("the SAML account key ID was not the signed NameID", in.AccountKey)
			}
			if in.Claims["email"] != "Employee@acme.example" || !reflect.DeepEqual(in.Claims["groups"], []any{"staff", "admins"}) {
				t.Fatal("the resolver did not receive the verified assertion attributes", in.Claims)
			}
			if in.IDTokenClaims != nil {
				t.Fatal("a SAML resolver input carried ID token claims", in.IDTokenClaims)
			}
			if in.User.Email != "employee@acme.example" || in.User.Name != "Local Employee" {
				t.Fatal("the SAML provider profile was not normalized", in.User)
			}
			var owner string
			if err := p.store.db.QueryRowContext(ctx, p.store.bind(`SELECT "userId" FROM "account" WHERE "providerId"=? AND "accountId"=?`), "acme", "employee").Scan(&owner); err != nil || owner != "selected" {
				t.Fatal("the SAML identity was not linked to the resolved user", owner, err)
			}

			mu.Lock()
			calls := append([]sso.Provisioning(nil), provisioned...)
			mu.Unlock()
			if len(calls) != 1 || calls[0].Token != nil || calls[0].UserInfo.Subject != "employee" || calls[0].User.ID != "selected" {
				t.Fatal("ProvisionUser received OIDC tokens or no profile for a SAML sign-in", calls)
			}

			before := sessions()
			mu.Lock()
			decision = sso.UserResolution{Action: sso.ResolveReject, Code: "SAML_BLOCKED", Message: "Not provisioned"}
			mu.Unlock()
			req, state = p.start(h, "acme")
			location, _ = samlOutcome(t, p.finish(h, "acme", req, state, nil, assert("blocked"), nil))
			if location.String() != "https://service.test/retry?error=SAML_BLOCKED&error_description=Not+provisioned" || sessions() != before {
				t.Fatal("a rejected SAML sign-in did not reach the error callback", location)
			}
		})
	}
}
