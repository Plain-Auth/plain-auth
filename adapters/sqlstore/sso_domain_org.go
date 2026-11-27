package sqlstore

import (
	"context"
	"crypto/rand"
	"errors"
	"sort"
	"strings"
	"time"

	org "github.com/Plain-Org/plain-auth/plugins/organization"
	"github.com/Plain-Org/plain-auth/plugins/sso"
)

var _ sso.DomainOrganizationStore = (*Store)(nil)

// SSODomainOrganization returns the first provider, by provider ID, that
// holds a current DNS proof for domain and belongs to an organization. A
// domain that such providers of several organizations serve is ambiguous.
func (s *Store) SSODomainOrganization(ctx context.Context, domain, userID, email string) (sso.DomainOrganization, bool, error) {
	var found sso.DomainOrganization
	exists, err := s.hasKeyOwnerTable(ctx, s.db, "organization")
	if err != nil || !exists {
		return found, false, err
	}
	rows, err := s.db.QueryContext(ctx, s.bind(`SELECT `+s.providerCols()+` FROM "ssoProvider" p WHERE `+browserProviderWhere+` AND p."organizationId" IS NOT NULL`))
	if err != nil {
		return found, false, err
	}
	// Close the scan before checking the proofs: a SQLite pool may expose
	// only one connection.
	var candidates []sso.BrowserProvider
	for rows.Next() {
		p, err := s.scanBrowserProvider(rows)
		if errors.Is(err, sso.ErrInvalidSAML) {
			continue
		}
		if err != nil {
			rows.Close()
			return found, false, err
		}
		if sso.DomainMatch(domain, p.Domain) >= 0 {
			candidates = append(candidates, p)
		}
	}
	if err = rows.Err(); err != nil {
		rows.Close()
		return found, false, err
	}
	if err = rows.Close(); err != nil {
		return found, false, err
	}
	// Byte order, where another runtime sorts by locale; it only picks the
	// provider handed to the role resolver.
	sort.Slice(candidates, func(i, j int) bool { return candidates[i].ProviderID < candidates[j].ProviderID })
	organizations := map[string]bool{}
	var first *sso.Provider
	for _, p := range candidates {
		verified, err := s.SSODomainVerified(ctx, p.Provider, p.Reference)
		if err != nil {
			return found, false, err
		}
		if !verified {
			continue
		}
		organizations[*p.OrganizationID] = true
		if first == nil {
			provider := p.Provider
			first = &provider
		}
	}
	if len(organizations) > 1 {
		return sso.DomainOrganization{Ambiguous: true}, false, nil
	}
	if first == nil {
		return found, false, nil
	}
	// A member or a pending invitee joins nothing, so the role is resolved
	// only for a user who would join; AddSSODomainMember checks again.
	var taken bool
	err = s.db.QueryRowContext(ctx, s.bind(`SELECT EXISTS(SELECT 1 FROM "member" WHERE "organizationId"=? AND "userId"=?) OR EXISTS(SELECT 1 FROM "invitation" WHERE "organizationId"=? AND "email"=? AND "status"='pending' AND "expiresAt">?)`),
		*first.OrganizationID, userID, *first.OrganizationID, strings.ToLower(email), s.date(time.Now().UTC())).Scan(&taken)
	if err != nil || taken {
		return found, false, err
	}
	return sso.DomainOrganization{Provider: *first}, true, nil
}

// AddSSODomainMember adds the user to the organization with role, within
// its member limit, unless the user is already a member or holds a pending
// invitation there.
func (s *Store) AddSSODomainMember(ctx context.Context, organizationID, userID, email, role string) error {
	return s.withMemberAdmission(ctx, func(admission *memberAdmission) error {
		tx, err := s.beginMembershipChange(ctx)
		if err != nil {
			return err
		}
		defer tx.Rollback()
		if err = s.lockOrganization(ctx, tx, organizationID); err != nil {
			return err
		}
		now := time.Now().UTC()
		var pending bool
		if err = tx.QueryRowContext(ctx, s.bind(`SELECT EXISTS(SELECT 1 FROM "invitation" WHERE "organizationId"=? AND "email"=? AND "status"='pending' AND "expiresAt">?)`), organizationID, strings.ToLower(email), s.date(now)).Scan(&pending); err != nil || pending {
			return err
		}
		err = s.checkNewMember(ctx, tx, organizationID, userID, admission, nil)
		if errors.Is(err, org.ErrAlreadyMember) {
			return nil
		}
		if err != nil {
			return err
		}
		if err = s.addMember(ctx, tx, org.Member{ID: rand.Text(), OrganizationID: organizationID, UserID: userID, Role: role, CreatedAt: now}); err != nil {
			return err
		}
		return tx.Commit()
	})
}
