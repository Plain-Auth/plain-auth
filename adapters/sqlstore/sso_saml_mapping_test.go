package sqlstore

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"encoding/xml"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	auth "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/plugins/sso"
	"github.com/Plain-Org/plain-auth/schema"
	"github.com/crewjam/saml"
	dsig "github.com/russellhaering/goxmldsig"
)

// A SAML directory's mapping chooses the email, name and declared user
// fields of a new user, and a portal sign-in without a host landing page
// lands on the directory's callbackUrl.
func TestEnterpriseSAMLDirectoryMapping(t *testing.T) {
	idpKey, idpCert, idpPEM := samlTestCertificate(t)
	const idpBase = "https://identity.example.test"
	const idpEntity, entry, spEntity = idpBase + "/metadata", idpBase + "/sso", "https://service.test/sp-mapped"
	fields := map[string]auth.UserField{"department": {Type: auth.FieldString}}
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			ctx := t.Context()
			must := func(err error) {
				t.Helper()
				if err != nil {
					t.Fatal(err)
				}
			}
			store, err := OpenWithAdditionalFields(ctx, dialect, organizationTestDSN(t, dialect), []string{"sso"}, schema.AdditionalFields{User: fields})
			must(err)
			defer store.Close()
			p, err := sso.New(sso.Options{SAML: &sso.SAMLOptions{TrustEmailVerified: true, AllowIDPInitiated: func(_ context.Context, d sso.SAMLDirectory) (bool, error) { return d.ProviderID == "mapped", nil }}})
			must(err)
			host, err := auth.New(auth.Options{BaseURL: "https://service.test", BasePath: "/identity", RateLimit: new(bool), Store: store, Secret: strings.Repeat("k", 32), EmailAndPassword: true, UserAdditionalFields: fields, Plugins: []auth.Plugin{p}})
			must(err)
			call := func(method, path, cookie string, body any) *httptest.ResponseRecorder {
				var buf bytes.Buffer
				if body != nil {
					must(json.NewEncoder(&buf).Encode(body))
				}
				req := httptest.NewRequest(method, "https://service.test/identity/"+path, &buf)
				req.Header.Set("Content-Type", "application/json")
				req.Header.Set("Origin", "https://service.test")
				if cookie != "" {
					req.Header.Set("Cookie", cookie)
				}
				w := httptest.NewRecorder()
				host.ServeHTTP(w, req)
				return w
			}
			signup := call("POST", "sign-up/email", "", map[string]any{"name": "Owner", "email": "owner@service.test", "password": "correct-horse-staple"})
			var owner string
			for _, c := range signup.Result().Cookies() {
				if strings.Contains(c.Name, "session_token") {
					owner = c.Name + "=" + c.Value
				}
			}
			if w := call("POST", "sso/register", owner, map[string]any{"providerId": "mapped", "issuer": idpEntity, "domain": "mapped.example", "samlConfig": map[string]any{
				"callbackUrl": "/directory-home", "spMetadata": map[string]any{"entityID": spEntity}, "entryPoint": entry, "cert": idpPEM, "idpMetadata": map[string]any{"entityID": idpEntity},
				"mapping": map[string]any{"email": "mail", "firstName": "first", "lastName": "last", "name": "display", "emailVerified": "verified", "extraFields": map[string]any{"department": "dept"}}}}); w.Code != 200 {
				t.Fatal("a SAML mapping with extraFields was refused at registration", w.Code, w.Body.String())
			}
			w := call("GET", "sso/saml2/sp/metadata?providerId=mapped", "", nil)
			var md saml.EntityDescriptor
			must(xml.Unmarshal(w.Body.Bytes(), &md))
			idp := &saml.IdentityProvider{Key: idpKey, Certificate: idpCert, MetadataURL: *mustTestURL(t, idpEntity), SSOURL: *mustTestURL(t, entry), ServiceProviderProvider: samlTestMetadata{spEntity: &md}, SignatureMethod: dsig.RSASHA256SignatureMethod}
			attr := func(name, value string) saml.Attribute {
				return saml.Attribute{Name: name, Values: []saml.AttributeValue{{Value: value}}}
			}
			portal := func(nameID string, attrs ...saml.Attribute) *httptest.ResponseRecorder {
				t.Helper()
				req, err := idp.NewIdpInitiatedRequest(httptest.NewRequest("GET", idpBase+"/portal", nil), spEntity, "")
				must(err)
				must((saml.DefaultAssertionMaker{}).MakeAssertion(req, &saml.Session{ID: "idp-" + nameID, Index: "index-" + nameID, CreateTime: time.Now(), ExpireTime: time.Now().Add(time.Hour), NameID: nameID, CustomAttributes: attrs}))
				req.Assertion.Subject.NameID.Value = nameID
				must(req.MakeAssertionEl())
				form, err := req.PostBinding()
				must(err)
				acs := httptest.NewRequest("POST", "https://service.test/identity/sso/saml2/sp/acs/mapped", strings.NewReader(url.Values{"SAMLResponse": {form.SAMLResponse}}.Encode()))
				acs.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				acs.Header.Set("Origin", idpBase)
				acs.Header.Set("Sec-Fetch-Dest", "document")
				done := httptest.NewRecorder()
				host.ServeHTTP(done, acs)
				return done
			}
			var verified bool
			user := func(email string) (name string, dept sql.NullString, found bool) {
				err := store.db.QueryRowContext(ctx, store.bind(`SELECT "name","department","emailVerified" FROM "user" WHERE "email"=?`), email).Scan(&name, &dept, &verified)
				return name, dept, err == nil
			}

			if w := portal("dir-user", attr("mail", "Directory.User@Mapped.Example"), attr("first", "Dana"), attr("last", "Lee"), attr("dept", "Research"), attr("email", "decoy@mapped.example"), attr("verified", "true")); w.Code != 302 || w.Header().Get("Location") != "https://service.test/directory-home" {
				t.Fatal("the portal sign-in did not land on the directory callbackUrl", w.Code, w.Header().Get("Location"))
			}
			name, dept, found := user("directory.user@mapped.example")
			if !found {
				t.Fatal("mapping.email did not choose the mail attribute")
			}
			if name != "Dana Lee" {
				t.Fatal("mapping.firstName and mapping.lastName did not form the name", name)
			}
			if dept.String != "Research" {
				t.Fatal("SAML extraFields did not fill the department user field", dept)
			}
			if !verified {
				t.Fatal("mapping.emailVerified with TrustEmailVerified did not verify the email")
			}
			teams := saml.Attribute{Name: "dept", Values: []saml.AttributeValue{{Value: "Research"}, {Value: "Sales"}}}
			if w := portal("display-user", attr("mail", "display@mapped.example"), attr("display", "Display Only"), teams); w.Code != 302 || w.Header().Get("Location") != "https://service.test/directory-home" {
				t.Fatal("a multi-valued mapped attribute refused the sign-up", w.Code, w.Header().Get("Location"))
			}
			name, dept, _ = user("display@mapped.example")
			if name != "Display Only" {
				t.Fatal("mapping.name did not supply the name without first and last names", name)
			}
			if dept.Valid || verified {
				t.Fatal("a multi-valued attribute filled a scalar user field, or a missing verification attribute verified the email", dept, verified)
			}
			// Without TrustEmailVerified the mapped verification is ignored.
			untrusted, err := sso.New(sso.Options{SAML: &sso.SAMLOptions{AllowIDPInitiated: func(_ context.Context, d sso.SAMLDirectory) (bool, error) { return d.ProviderID == "mapped", nil }}})
			must(err)
			host, err = auth.New(auth.Options{BaseURL: "https://service.test", BasePath: "/identity", RateLimit: new(bool), Store: store, Secret: strings.Repeat("k", 32), EmailAndPassword: true, UserAdditionalFields: fields, Plugins: []auth.Plugin{untrusted}})
			must(err)
			if w := portal("unverified-user", attr("mail", "unverified@mapped.example"), attr("verified", "true")); w.Code != 302 || w.Header().Get("Location") != "https://service.test/directory-home" {
				t.Fatal("the untrusted portal sign-in failed", w.Code, w.Header().Get("Location"))
			}
			if _, _, found := user("unverified@mapped.example"); !found || verified {
				t.Fatal("mapping.emailVerified verified the email without TrustEmailVerified", found, verified)
			}
		})
	}
}
