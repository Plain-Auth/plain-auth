package sqlstore

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/xml"
	"errors"
	org "github.com/Plain-Org/plain-auth/plugins/organization"
	"strings"
	"testing"
	"time"

	"github.com/Plain-Org/plain-auth/client"
	"github.com/Plain-Org/plain-auth/plugins/sso"
	"github.com/crewjam/saml"
)

func idpDocument(t *testing.T, entityID, endpoint string, keys ...*x509.Certificate) string {
	t.Helper()
	role := saml.IDPSSODescriptor{SingleSignOnServices: []saml.Endpoint{{Binding: saml.HTTPRedirectBinding, Location: endpoint}}}
	role.ProtocolSupportEnumeration = "urn:oasis:names:tc:SAML:2.0:protocol"
	for _, cert := range keys {
		data := saml.X509Data{X509Certificates: []saml.X509Certificate{{Data: base64.StdEncoding.EncodeToString(cert.Raw)}}}
		role.KeyDescriptors = append(role.KeyDescriptors, saml.KeyDescriptor{Use: "signing", KeyInfo: saml.KeyInfo{X509Data: data}})
	}
	raw, err := xml.Marshal(saml.EntityDescriptor{EntityID: entityID, IDPSSODescriptors: []saml.IDPSSODescriptor{role}})
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func testSAMLMetadataRotation(t *testing.T, first, second *Store, owner, outsider *client.Client, cfg sso.SAMLConfig, oldKey *rsa.PrivateKey, oldCert *x509.Certificate, pending func(*rsa.PrivateKey, *x509.Certificate) func() string) {
	t.Helper()
	ctx := t.Context()
	must := func(e error) {
		t.Helper()
		if e != nil {
			t.Fatal(e)
		}
	}
	newKey, newCert, _ := samlTestCertificate(t)
	entity, entry := cfg.IDPMetadata.EntityID, cfg.EntryPoint
	oldDoc := idpDocument(t, entity, entry, oldCert)
	both := idpDocument(t, entity, entry, oldCert, newCert)
	newDoc := idpDocument(t, entity, entry, newCert)
	// XML alone supplies the IdP entity, endpoint and signing anchors.
	imported := cfg
	imported.Certificates = nil
	imported.EntryPoint = "https://manual.example.test/unused"
	imported.IDPMetadata = sso.SAMLIDPMetadata{Metadata: oldDoc}
	registered, e := owner.RegisterSAMLProvider(ctx, client.RegisterSAMLProviderRequest{ProviderID: "imported", Domain: "imported.example", Issuer: "https://sp.example.test/issuer", SAML: imported})
	must(e)
	if registered.ID == "" {
		t.Fatal("missing imported registration")
	}
	p, e := first.FindBrowserProvider(ctx, sso.Selector{ProviderID: "imported", Protocol: "saml"})
	must(e)
	if p.SAML.IdentityProviderEntityID() != entity {
		t.Fatal("wrong imported authority")
	}
	// A vacant directory may adopt a new identity, while an expired document
	// and a too-large canonical MySQL TEXT value leave the catalog intact.
	replacementEntity := "urn:example:unlinked-directory"
	vacant, e := owner.UpdateSAMLMetadata(ctx, "imported", idpDocument(t, replacementEntity, entry, newCert))
	must(e)
	if vacant.DomainVerified {
		t.Fatal("new authority inherited an unverified directory")
	}
	invalid := strings.Replace(newDoc, "<EntityDescriptor ", "<EntityDescriptor validUntil=\"2000-01-01T00:00:00Z\" ", 1)
	if _, e = owner.UpdateSAMLMetadata(ctx, "imported", invalid); e == nil {
		t.Fatal("expired metadata accepted")
	}
	for _, invalidDoc := range []string{
		strings.Replace(newDoc, `use="signing"`, `use="encryption"`, 1),
		strings.Replace(newDoc, saml.HTTPRedirectBinding, saml.HTTPPostBinding, 1),
		`<EntitiesDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata">` + newDoc + `</EntitiesDescriptor>`,
		newDoc + newDoc, "https://idp.example.test/remote-metadata.xml",
		strings.Repeat(" ", 100*1024) + oldDoc,
	} {
		if _, e := owner.UpdateSAMLMetadata(ctx, "imported", invalidDoc); e == nil {
			t.Fatal("unusable inline metadata accepted")
		}
	}
	if first.dialect == "mysql" {
		padded := strings.Replace(newDoc, "</EntityDescriptor>", strings.Repeat(" ", 65535)+"</EntityDescriptor>", 1)
		if _, e = owner.UpdateSAMLMetadata(ctx, "imported", padded); e == nil {
			t.Fatal("oversized MySQL configuration accepted")
		}
	}
	if _, e = outsider.UpdateSAMLMetadata(ctx, "work", newDoc); e == nil {
		t.Fatal("another manager changed a personal IdP")
	}
	queued := pending(oldKey, oldCert)
	view, e := owner.UpdateSAMLMetadata(ctx, "work", both)
	must(e)
	if view.SAML == nil || view.Type != "saml" || !view.DomainVerified {
		t.Fatal("metadata rotation lost the verified domain", view)
	}
	if target := queued(); !strings.Contains(target, "invalid_state") {
		t.Fatal("old request survived certificate rotation", target)
	}
	for _, v := range []struct {
		key  *rsa.PrivateKey
		cert *x509.Certificate
	}{{oldKey, oldCert}, {newKey, newCert}} {
		if target := pending(v.key, v.cert)(); !strings.HasSuffix(target, "/home") {
			t.Fatal("cert overlap", target)
		}
	}
	for _, change := range []string{idpDocument(t, "urn:example:other", entry, newCert), idpDocument(t, entity, "https://other.example.test/login", newCert)} {
		if _, e := owner.UpdateSAMLMetadata(ctx, "work", change); e == nil {
			t.Fatal("linked authority changed")
		}
	}
	_, e = owner.UpdateSAMLMetadata(ctx, "work", newDoc)
	must(e)
	if target := pending(oldKey, oldCert)(); !strings.Contains(target, "invalid_saml_response") {
		t.Fatal("retired certificate accepted", target)
	}
	if target := pending(newKey, newCert)(); !strings.HasSuffix(target, "/home") {
		t.Fatal("new signing authority rejected", target)
	}
	current, e := first.FindBrowserProvider(ctx, sso.Selector{ProviderID: "work", Protocol: "saml"})
	must(e)
	session, e := owner.GetSession(ctx)
	must(e)
	actor := sso.Actor{UserID: session.User.ID, SessionToken: session.Session.Token}
	// An active session only inherits the directory's current organization role.
	other, e := outsider.GetSession(ctx)
	must(e)
	now := time.Now()
	team := org.Organization{ID: "xml-organization", Name: "XML tenant", Slug: "xml-tenant", CreatedAt: now}
	must(first.CreateOrganization(ctx, team, org.Member{ID: "xml-owner", UserID: actor.UserID, OrganizationID: team.ID, Role: "owner", CreatedAt: now}, session.Session.ID, true))
	_, e = owner.RegisterSAMLProvider(ctx, client.RegisterSAMLProviderRequest{ProviderID: "org-xml", Domain: "org-xml.example", OrganizationID: team.ID, Issuer: "https://sp.example.test/issuer", SAML: imported})
	must(e)
	if _, e = outsider.UpdateSAMLMetadata(ctx, "org-xml", newDoc); e == nil {
		t.Fatal("foreign organization account changed IdP metadata")
	}
	member := org.Member{ID: "xml-admin", UserID: other.User.ID, OrganizationID: team.ID, Role: "admin", CreatedAt: now}
	must(first.AddOrganizationMember(ctx, member, ""))
	_, e = outsider.UpdateSAMLMetadata(ctx, "org-xml", newDoc)
	must(e)
	_, e = first.UpdateOrganizationMemberRole(ctx, actor.UserID, actor.SessionToken, org.UpdateMemberRoleRequest{OrganizationID: team.ID, MemberID: member.ID, Roles: []string{"member"}})
	must(e)
	currentOrg, e := first.FindBrowserProvider(ctx, sso.Selector{ProviderID: "org-xml", Protocol: "saml"})
	must(e)
	_, e = second.UpdateSSOMetadata(ctx, sso.Actor{UserID: other.User.ID, SessionToken: other.Session.Token}, "org-xml", currentOrg.ID, currentOrg.Reference, both, nil)
	if !errors.Is(e, sso.ErrForbidden) {
		t.Fatal("demoted organization member retained metadata authority", e)
	}
	observed := false
	var readErr error
	guard := func(gc context.Context, m sso.ProviderMutation) error {
		read, cancel := context.WithTimeout(gc, 2*time.Second)
		defer cancel()
		_, readErr = second.FindBrowserProvider(read, sso.Selector{ProviderID: "work", Protocol: "saml"})
		observed = m.Action == "update" && m.ID == current.ID && m.Reference == current.Reference && m.LinkedAccounts > 0 && m.AuthenticationBoundaryChanged
		return errors.New("denied by host")
	}
	_, e = second.UpdateSSOMetadata(ctx, actor, "work", current.ID, current.Reference, both, guard)
	if !errors.Is(e, sso.ErrMutationRejected) || !observed {
		t.Fatal("mutation guard did not receive locked authorization", e)
	}
	if readErr != nil {
		t.Fatal("the metadata guard could not read the store, so it ran inside the transaction", readErr)
	}
	if _, e = second.UpdateSSOMetadata(ctx, sso.Actor{UserID: actor.UserID, SessionToken: "stale"}, "work", current.ID, current.Reference, both, nil); !errors.Is(e, sso.ErrUnauthenticated) {
		t.Fatal("stale session metadata update", e)
	}
	gate := make(chan struct{})
	results := make(chan error, 2)
	for i, store := range []*Store{first, second} {
		go func() {
			<-gate
			_, err := store.UpdateSSOMetadata(ctx, actor, "work", current.ID, current.Reference, []string{both, oldDoc}[i], nil)
			results <- err
		}()
	}
	close(gate)
	a, b := <-results, <-results
	if !((a == nil && errors.Is(b, sso.ErrChanged)) || (b == nil && errors.Is(a, sso.ErrChanged))) {
		t.Fatal("concurrent XML revisions", a, b)
	}
}
