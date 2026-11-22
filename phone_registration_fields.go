package plainauth

import (
	"context"
	"errors"
	"strings"
)

// PhoneRegistrationStore consumes the exact verified proof and atomically writes the
// user, profile columns and optional first session. A profile validation error spends
// the proof only on first registration. Existing users and links keep their fields.
type PhoneRegistrationStore interface {
	ApplyPhoneRegistration(context.Context, PhoneAccountAction, RegistrationUserFields) (PhoneAccountResult, error)
}

var phoneVerificationKeys = [...]string{"phoneNumber", "code", "disableSession", "updatePhoneNumber"}

// CheckProfileKeys prevents a caller from placing a verification input in the profile.
func (in PhoneVerificationInput) CheckProfileKeys() error {
	for _, key := range phoneVerificationKeys {
		if _, exists := in.AdditionalFields[key]; exists {
			return validationError("Additional user field " + key + " conflicts with a phone verification input")
		}
	}
	return nil
}

// Run application resolvers outside storage locks, only for a verified new number.
// The write rechecks this exact proof generation and its current owner under lock.
func (a *Auth) preparePhoneRegistration(ctx context.Context, act *PhoneAccountAction, in PhoneVerificationInput, requestedVerified any) (RegistrationUserFields, error) {
	var profile RegistrationUserFields
	store := a.opts.Store.(PhoneAccountStore)
	proof, err := store.ReadPhoneOTP(ctx, in.PhoneNumber, PhoneVerify)
	if err != nil {
		return profile, err
	}
	_, denied := act.Use.Check(proof)
	if proof == nil || act.Use.ProviderProof != "" && act.Use.ProviderProof != proof.ID {
		return profile, denied
	}
	act.Use.ProviderProof, act.Use.ProviderAccepted = proof.ID, denied == nil
	if denied != nil {
		return profile, store.ConsumePhoneOTP(ctx, act.Use)
	}
	if proof.OwnerBound {
		if proof.BoundOwner != "" {
			return profile, nil
		}
	} else {
		// Proofs from other writers may have no local issuance receipt.
		owner, _, err := store.PhoneCredential(ctx, in.PhoneNumber)
		if err != nil && !errors.Is(err, ErrNotFound) {
			return profile, err
		}
		if owner.ID != "" {
			return profile, nil
		}
	}
	if len(a.opts.UserAdditionalFields) > 0 {
		if profile.err = in.CheckProfileKeys(); profile.err == nil {
			profile.values, profile.err = a.prepareUserFields(in.AdditionalFields, true, false)
		}
		if profile.err != nil {
			return profile, nil
		}
	}
	if !emptyUserInput(requestedVerified) {
		profile.err = &APIError{400, "FIELD_NOT_ALLOWED", "phoneNumberVerified is not allowed to be set"}
		return profile, nil
	}
	options := a.phoneNumber.SignUpOnVerification
	addr := strings.ToLower(options.GetTempEmail(in.PhoneNumber))
	if !emailPattern.MatchString(addr) || strings.Contains(addr, "..") {
		return profile, errors.New("phone-number: temporary email address is invalid")
	}
	name := in.PhoneNumber
	if options.GetTempName != nil {
		name = options.GetTempName(in.PhoneNumber)
	}
	now := a.now().UTC()
	act.Create = &User{ID: randomID(), Email: addr, Name: name, CreatedAt: now, UpdatedAt: now}
	return profile, nil
}
