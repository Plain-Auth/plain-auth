package plainauth

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strconv"
	"strings"
	"time"
)

// EmailVerificationReceipt is an expiring, single-use continuation between an
// accepted proof and its next storage transaction. Value contains a digest.
type EmailVerificationReceipt struct {
	Identifier, Value string
	ExpiresAt         time.Time
}

// ValidScope limits cleanup operations to this feature's canonical namespace.
func (r EmailVerificationReceipt) ValidScope() bool {
	owner, ok := strings.CutPrefix(r.Identifier, "mail-observer-code:")
	if !ok {
		owner, ok = strings.CutPrefix(r.Identifier, "mail-observer-session:")
	}
	value, err := base64.RawURLEncoding.Strict().DecodeString(r.Value)
	return ok && owner != "" && err == nil && len(value) == sha256.Size
}

func emailVerificationReceipt(stage string, owner User, expires time.Time, fields ...string) EmailVerificationReceipt {
	fields = append(fields, stage, owner.ID, owner.Email, strconv.FormatInt(owner.UpdatedAt.UnixMilli(), 10), strconv.FormatInt(expires.UnixMilli(), 10))
	data, _ := json.Marshal(fields) // A slice of strings is always encodable.
	digest := sha256.Sum256(data)
	return EmailVerificationReceipt{Identifier: "mail-observer-" + stage + ":" + owner.ID, Value: base64.RawURLEncoding.EncodeToString(digest[:]), ExpiresAt: expires}
}

func (v EmailVerificationAttempt) receiptFields() []string {
	fields := []string{v.ProofID, v.OwnerID, v.Email, v.ExistingToken, strconv.FormatBool(v.AlwaysCreateSession)}
	if s := v.NewSession; s != nil {
		fields = append(fields, s.ID, s.Token, s.UserID, s.CredentialType, s.IPAddress, s.UserAgent, strconv.FormatInt(s.CreatedAt.UnixNano(), 10), strconv.FormatInt(s.UpdatedAt.UnixNano(), 10), strconv.FormatInt(s.ExpiresAt.UnixNano(), 10))
		if s.storageFields != nil {
			data, _ := json.Marshal(s.storageFields.columns)
			fields = append(fields, "session-fields", string(data), s.storageFields.invalid)
		}
		for _, field := range []*string{s.ActiveOrganizationID, s.ActiveTeamID, s.ImpersonatedBy} {
			if field == nil {
				fields = append(fields, "null")
			} else {
				fields = append(fields, "value", *field)
			}
		}
	}
	return fields
}

// SessionReceipt binds a session handoff to the proved account and exact
// candidate. A replacement token or a second finish cannot claim the receipt.
func (v EmailVerificationAttempt) SessionReceipt(owner User) EmailVerificationReceipt {
	return emailVerificationReceipt("session", owner, v.ExpiresAt, v.receiptFields()...)
}

// EmailOTPObservation carries the single-use continuation for a spent code.
type EmailOTPObservation struct {
	ID, ExistingToken string
	ExpiresAt         time.Time
	NewSession        *StoredSession
}

func (req EmailOTPRequest) ObservationAttempt(owner User) EmailVerificationAttempt {
	o := req.Observation
	v := EmailVerificationAttempt{ProofID: o.ID, Email: req.Email, OwnerID: owner.ID, Now: req.Now, ExpiresAt: o.ExpiresAt, ExistingToken: o.ExistingToken, AlwaysCreateSession: true}
	if o.NewSession != nil {
		s := *o.NewSession
		s.UserID = owner.ID
		v.NewSession = &s
	}
	return v
}

func (req EmailOTPRequest) ObservationReceipt(owner User) EmailVerificationReceipt {
	v := req.ObservationAttempt(owner)
	fields := append(v.receiptFields(), string(req.Purpose))
	if src := req.Source; src != nil {
		fields = append(fields, src.UserID, src.Email, src.SessionToken)
	}
	return emailVerificationReceipt("code", owner, v.ExpiresAt, fields...)
}
