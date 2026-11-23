package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"slices"
	"time"

	auth "github.com/Plain-Auth/plain-auth"
	org "github.com/Plain-Auth/plain-auth/plugins/organization"
)

func configureInvitationCreation(o *org.Options, path, mode string) {
	record := func(phase string, inv any, group org.Organization, actor auth.User) error {
		file, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
		if err != nil {
			return err
		}
		defer file.Close()
		return json.NewEncoder(file).Encode(map[string]any{"phase": phase, "invitation": inv, "organization": group, "actor": actor})
	}
	if mode == "prepare" {
		o.BeforeCreateInvitation = func(_ context.Context, e org.InvitationCreationEvent) (*org.InvitationChanges, error) {
			if err := record("before", e.Invitation, e.Organization, e.Inviter); err != nil {
				return nil, err
			}
			switch e.Invitation.Email {
			case "veto@example.test":
				return nil, errors.New("private preparation fixture")
			case "custom@example.test":
				email := "processed@example.test"
				expiration := time.Date(time.Now().UTC().Year()+1, time.January, 5, 12, 0, 0, 0, time.UTC)
				teams := slices.Clone(e.Invitation.TeamIDs)
				slices.Reverse(teams)
				return &org.InvitationChanges{Email: &email, Roles: []string{"member"}, TeamIDs: teams, ExpiresAt: &expiration}, nil
			case "wide@example.test":
				return &org.InvitationChanges{TeamIDs: []string{}}, nil
			}
			return nil, nil
		}
	}
	if mode == "with-mail" || mode == "prepare" {
		o.SendInvitationEmail = func(_ context.Context, e org.InvitationDelivery) error {
			if err := record("mail", e.Invitation, e.Organization, e.Inviter.User); err != nil {
				return err
			}
			if e.Invitation.Email == "mail-failure@example.test" {
				return errors.New("fixture delivery failed")
			}
			return nil
		}
	}
	o.AfterCreateInvitation = func(_ context.Context, e org.InvitationDecisionEvent) error {
		if err := record("created", e.Invitation, e.Organization, e.Actor); err != nil {
			return err
		}
		if e.Invitation.Email == "hook-failure@example.test" {
			return errors.New("private creation fixture")
		}
		return nil
	}
}
