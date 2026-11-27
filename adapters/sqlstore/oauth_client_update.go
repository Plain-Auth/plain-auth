package sqlstore

import (
	"context"
	"encoding/json"
	"strings"

	op "github.com/Plain-Org/plain-auth/plugins/oauthprovider"
)

// UpdateOAuthClient writes an owner's validated registration fields after
// checking, under a row lock, that the client is still the one validated.
func (s *Store) UpdateOAuthClient(ctx context.Context, u op.ClientUpdate) (op.ClientDetails, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return op.ClientDetails{}, err
	}
	defer tx.Rollback()
	locked, err := scanClientDetails(tx.QueryRowContext(ctx, s.readForUpdate(clientDetailsSelect+localClientFilter), u.ClientID))
	if err != nil {
		return op.ClientDetails{}, err
	}
	if err := u.CheckTarget(locked); err != nil {
		return op.ClientDetails{}, err
	}
	m := u.Metadata
	text := func(v *string) any {
		if v == nil {
			return nil
		}
		return *v
	}
	list := func(v []string) any {
		if v == nil {
			v = []string{}
		}
		raw, _ := json.Marshal(v) // A string slice always encodes.
		return string(raw)
	}
	var sets []string
	var args []any
	set := func(column string, value any) {
		sets = append(sets, `"`+column+`"=?`)
		args = append(args, value)
	}
	for _, field := range u.Fields {
		switch field {
		case "redirect_uris":
			set("redirectUris", list(m.RedirectURIs))
		case "scope":
			set("scopes", list(strings.Fields(m.Scope)))
		case "client_name":
			set("name", text(m.Name))
		case "client_uri":
			set("uri", text(m.URI))
		case "logo_uri":
			set("icon", text(m.LogoURI))
		case "contacts":
			set("contacts", list(m.Contacts))
		case "tos_uri":
			set("tos", text(m.TermsURI))
		case "policy_uri":
			set("policy", text(m.PolicyURI))
		case "software_id":
			set("softwareId", text(m.SoftwareID))
		case "software_version":
			set("softwareVersion", text(m.SoftwareVersion))
		case "software_statement":
			set("softwareStatement", text(m.SoftwareStatement))
		case "post_logout_redirect_uris":
			set("postLogoutRedirectUris", list(m.PostLogoutRedirectURIs))
		case "backchannel_logout_uri":
			set("backchannelLogoutUri", text(m.BackchannelLogoutURI))
		case "backchannel_logout_session_required":
			var v any
			if m.BackchannelLogoutSessionRequired != nil {
				v = *m.BackchannelLogoutSessionRequired
			}
			set("backchannelLogoutSessionRequired", v)
		case "application_type":
			set("applicationType", m.ApplicationType)
		case "grant_types":
			set("grantTypes", list(m.GrantTypes))
		case "response_types":
			set("responseTypes", list(m.ResponseTypes))
		}
	}
	if u.ClearMachineScopes {
		set("clientCredentialsScopes", "[]")
	}
	set("updatedAt", s.date(u.UpdatedAt))
	args = append(args, u.ClientID)
	if _, err := tx.ExecContext(ctx, s.bind(`UPDATE "oauthClient" SET `+strings.Join(sets, ",")+localClientFilter), args...); err != nil {
		return op.ClientDetails{}, err
	}
	updated, err := scanClientDetails(tx.QueryRowContext(ctx, s.bind(clientDetailsSelect+localClientFilter), u.ClientID))
	if err != nil {
		return op.ClientDetails{}, err
	}
	return updated, tx.Commit()
}
