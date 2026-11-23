package organization

import (
	"context"
	"errors"
	"testing"

	auth "github.com/Plain-Auth/plain-auth"
)

type basicSelectionStore struct {
	Store
	current           string
	denyResolvedWrite bool
	clearError        error
}

func (s *basicSelectionStore) OrganizationForMember(_ context.Context, user, id, slug string) (*Organization, error) {
	if user != "user" {
		return nil, ErrUnauthenticated
	}
	if id == "home" || slug == "home" && id == "" {
		return &Organization{ID: "home", Slug: "home"}, nil
	}
	if id == "other" || slug == "other" {
		return nil, ErrNotMember
	}
	return nil, ErrNotFound
}

func (s *basicSelectionStore) SetActiveOrganization(_ context.Context, session, user string, id *string) error {
	if session != "login" || user != "user" {
		return ErrUnauthenticated
	}
	if id == nil {
		if s.clearError != nil {
			return s.clearError
		}
		s.current = ""
		return nil
	}
	if s.denyResolvedWrite {
		return ErrNotMember
	}
	s.current = *id
	return nil
}

func TestSelectionWithBasicStore(t *testing.T) {
	existing := "home"
	writeError := errors.New("could not persist the clear")
	signed := &auth.SessionResult{Session: auth.Session{ID: "login", ActiveOrganizationID: &existing}, User: auth.User{ID: "user"}}
	for _, tc := range []struct {
		name                  string
		input                 *OrganizationSelection
		deniedWrite           bool
		clearError, wantError error
		want                  string
	}{
		{"implicit", &OrganizationSelection{}, false, nil, nil, "home"},
		{"ID before slug", &OrganizationSelection{OrganizationID: "home", OrganizationSlug: "other"}, false, nil, nil, "home"},
		{"unknown slug", &OrganizationSelection{OrganizationSlug: "unknown"}, false, nil, ErrNotFound, "home"},
		{"unknown ID", &OrganizationSelection{OrganizationID: "unknown"}, false, nil, ErrNotMember, ""},
		{"foreign slug", &OrganizationSelection{OrganizationSlug: "other"}, false, nil, ErrNotMember, ""},
		{"membership lost before save", &OrganizationSelection{OrganizationSlug: "home"}, true, nil, ErrNotMember, ""},
		{"clear failed", &OrganizationSelection{OrganizationID: "other"}, false, writeError, writeError, "home"},
		{"explicit clear", nil, false, nil, nil, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := &basicSelectionStore{current: existing, denyResolvedWrite: tc.deniedWrite, clearError: tc.clearError}
			got, err := (Options{Store: store}).selectWithStore(t.Context(), signed, tc.input)
			if !errors.Is(err, tc.wantError) || store.current != tc.want {
				t.Fatalf("selection %q, error %v", store.current, err)
			}
			if err != nil || tc.want == "" {
				if got != nil {
					t.Fatal("expected an empty result")
				}
			} else if got == nil || got.ID != tc.want {
				t.Fatal("expected the selected organization", got)
			}
		})
	}
}
