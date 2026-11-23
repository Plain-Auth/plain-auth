package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"

	auth "github.com/Plain-Auth/plain-auth"
	org "github.com/Plain-Auth/plain-auth/plugins/organization"
)

func configureOrganizationProfileHooks(o *org.Options, path string) {
	record := func(stage string, organization any, user auth.User, member org.Member) error {
		file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
		if err != nil {
			return err
		}
		defer file.Close()
		return json.NewEncoder(file).Encode(map[string]any{"stage": stage, "organization": organization, "user": user, "member": member})
	}
	o.BeforeUpdateOrganization = func(ctx context.Context, event org.BeforeProfileUpdate) (*org.ProfileUpdate, error) {
		if err := record("before", event.Organization, event.User, event.Member); err != nil {
			return nil, err
		}
		if event.Organization.Name == nil {
			return nil, nil
		}
		switch *event.Organization.Name {
		case "before-failure":
			return nil, errors.New("private organization fixture")
		case "normalize":
			name := "normalized"
			return &org.ProfileUpdate{Name: &name, ClearLogo: true}, nil
		}
		return nil, nil
	}
	o.AfterUpdateOrganization = func(ctx context.Context, event org.AfterProfileUpdate) error {
		if err := record("after", event.Organization, event.User, event.Member); err != nil {
			return err
		}
		if event.Organization != nil && event.Organization.Name == "after-failure" {
			return errors.New("private organization fixture")
		}
		return nil
	}
}

func configureDecisionHooks(o *org.Options, path string) {
	record := func(phase string) org.InvitationDecisionHook {
		return func(_ context.Context, event org.InvitationDecisionEvent) error {
			f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
			if err != nil {
				return err
			}
			defer f.Close()
			err = json.NewEncoder(f).Encode(map[string]any{"phase": phase, "actor": event.Actor, "invitation": event.Invitation, "organization": event.Organization})
			if err == nil && event.Organization.Slug == phase {
				return errors.New("private invitation fixture")
			}
			return err
		}
	}
	o.BeforeRejectInvitation, o.AfterRejectInvitation = record("before-reject"), record("after-reject")
	o.BeforeCancelInvitation, o.AfterCancelInvitation = record("before-cancel"), record("after-cancel")
}
