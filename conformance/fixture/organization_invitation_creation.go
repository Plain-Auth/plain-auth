package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"

	auth "github.com/Plain-Auth/plain-auth"
	org "github.com/Plain-Auth/plain-auth/plugins/organization"
)

func configureInvitationCreation(o *org.Options, path, mode string) {
	record := func(phase string, inv org.Invitation, group org.Organization, actor auth.User) error {
		file, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
		if err != nil {
			return err
		}
		defer file.Close()
		return json.NewEncoder(file).Encode(map[string]any{"phase": phase, "invitation": inv, "organization": group, "actor": actor})
	}
	if mode == "with-mail" {
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
