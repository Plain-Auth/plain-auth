package organization

import (
	"bytes"
	"context"
	"errors"
	"strings"

	authn "github.com/Plain-Auth/plain-auth"
)

// BeforeMemberAddition describes a membership about to be granted to User in
// Organization, either to an organization's creator or through
// Service.AddMember.
type BeforeMemberAddition struct {
	Member       Member
	User         authn.User
	Organization Organization
}

// MemberOverride replaces fields of a proposed membership. Nil Roles keeps
// the proposed roles; an empty slice grants membership with no roles.
type MemberOverride struct {
	Roles []string
}

// AfterMemberAddition describes a committed membership.
type AfterMemberAddition struct {
	Member       Member
	User         authn.User
	Organization Organization
}

// MemberCandidate is the account and organization a trusted grant names.
type MemberCandidate struct {
	User         authn.User
	Organization Organization
}

// MemberAdditionStore checks a trusted grant without writing, so the host's
// member hooks see only grants that can proceed. The write rechecks them.
type MemberAdditionStore interface {
	PrepareMemberAddition(ctx context.Context, member Member, teamID string) (MemberCandidate, error)
}

var errMemberHookStore = errors.New("organization: member hooks for trusted grants require a MemberAdditionStore")

func (o Options) beforeAddMember(ctx context.Context, member *Member, user authn.User, group Organization) error {
	before := o.BeforeAddMember
	if before == nil {
		return nil
	}
	in, err := memberAdditionEvent(*member, user, group)
	if err != nil {
		return err
	}
	override, err := before(ctx, BeforeMemberAddition(in))
	if err != nil {
		return err
	}
	if override != nil && override.Roles != nil {
		member.Role = strings.Join(NormalizeRoles(override.Roles...), ",")
	}
	return nil
}

func (o Options) afterAddMember(ctx context.Context, member Member, user authn.User, group Organization) error {
	after := o.AfterAddMember
	if after == nil {
		return nil
	}
	in, err := memberAdditionEvent(member, user, group)
	if err != nil {
		return err
	}
	return after(ctx, in)
}

// memberAdditionEvent detaches the values handed to host code.
func memberAdditionEvent(member Member, user authn.User, group Organization) (AfterMemberAddition, error) {
	user, err := detachedUser(user)
	if err != nil {
		return AfterMemberAddition{}, err
	}
	group.Metadata = bytes.Clone(group.Metadata)
	if group.Logo != nil {
		logo := *group.Logo
		group.Logo = &logo
	}
	return AfterMemberAddition{Member: member, User: user, Organization: group}, nil
}
