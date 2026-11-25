package plainauth

import (
	"context"
	"time"
)

// VerificationHookSet tells a plugin's ValidateVerificationStore which
// verification database hooks are set.
type VerificationHookSet struct {
	// CreateBefore reports create before hooks, which may decline a record.
	CreateBefore bool
	// Delete reports delete hooks, which read a record before it is spent.
	Delete bool
}

// CreateVerification runs the verification create database hooks around
// save, for a plugin that keeps a verification record in its own store, such
// as a passkey challenge or a wallet nonce. rec describes the record save
// stores. Hooks may log it, so it must never carry the token, nonce, code or
// challenge that redeems the record, nor the data stored with it: give it the
// record's kind as Identifier, the stored row's ID or one derived from the
// stored key by a one-way function, its owner if any, and its expiry, which
// CreateVerification truncates to the millisecond in UTC.
//
// declined reports that a before hook cancelled the create: save was not
// called and nothing is stored. An error from save or an after hook is
// returned as it is; after an after hook's error the record stays stored.
// The hooks and save run with the request's context, outside any transaction
// save opens.
func (c EndpointContext) CreateVerification(rec VerificationRecord, save func(context.Context) error) (declined bool, err error) {
	ctx := c.Request.Context()
	rec.ExpiresAt = rec.ExpiresAt.UTC().Truncate(time.Millisecond)
	return c.Auth.createVerification(ctx, rec, func() error { return save(ctx) })
}

// SpendVerification runs the verification delete database hooks around
// spend, for a plugin that spends a verification record in its own store.
// When delete hooks are set, find first reads the record spend is about to
// spend, without spending or locking it, and returns ErrNotFound for one that
// is unknown or expired, which runs no hooks; the before hooks run on the
// record it returns, built under CreateVerification's rules. spend returns
// ErrNotFound when it spent nothing.
//
// refused reports a before hook's cancel, which keeps the record and does not
// call spend; a spend that spent nothing; and a spend of a record find did
// not see, whose hooks never ran. The plugin answers each as an unusable
// record. The after hooks run once spend succeeded, before SpendVerification
// returns; their error is returned with the record spent. With no delete hook
// set, find is not called. A plugin that calls SpendVerification sets
// Plugin.ValidateVerificationStore, so that New refuses delete hooks on a
// store without a finder.
func (c EndpointContext) SpendVerification(find func(context.Context) (VerificationRecord, error), spend func(context.Context) error) (refused bool, err error) {
	ctx := c.Request.Context()
	return c.Auth.spendVerification(ctx, func() (VerificationRecord, error) {
		rec, err := find(ctx)
		rec.ExpiresAt = rec.ExpiresAt.UTC().Truncate(time.Millisecond)
		return rec, err
	}, func() error { return spend(ctx) })
}
