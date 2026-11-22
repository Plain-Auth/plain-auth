package plainauth

import (
	"context"
	"slices"
	"strings"
)

func (o *AdminOptions) protectedIdentity(u User) bool {
	if slices.Contains(o.AdminUserIDs, u.ID) {
		return true
	}
	for _, r := range strings.Split(u.Role, ",") {
		if slices.Contains(o.AdminRoles, r) {
			return true
		}
	}
	return false
}

func (a *Auth) adminPhoneFields(ctx context.Context, actor User, u *User, data map[string]any, creating bool) error {
	number, hasNumber := data["phoneNumber"]
	flag, hasFlag := data["phoneNumberVerified"]
	if !hasNumber && !hasFlag {
		if creating && a.phoneNumber != nil {
			u.PhoneNumberFields = &PhoneNumberFields{}
		}
		return nil
	}
	if a.phoneNumber == nil {
		return validationError("Unknown user field")
	}
	denied := &APIError{403, "YOU_ARE_NOT_ALLOWED_TO_SET_USERS_PHONE_NUMBER", "You are not allowed to update users phone number"}
	if !a.admin.HasPermission(actor.ID, actor.Role, AdminPermissions{"user": {"set-phone"}}) {
		return denied
	}
	if a.admin.protectedIdentity(*u) && !a.admin.protectedIdentity(actor) {
		return denied
	}
	f := PhoneNumberFields{}
	if u.PhoneNumberFields != nil {
		f = *u.PhoneNumberFields
	}
	var verified bool
	if hasFlag && flag != nil {
		value, ok := flag.(bool)
		if !ok {
			return validationError("phoneNumberVerified must be a boolean or null")
		}
		verified = value
	}
	if hasNumber {
		if number == nil {
			no := false
			u.PhoneNumberFields = &PhoneNumberFields{PhoneNumberVerified: &no}
			return nil
		}
		n, ok := number.(string)
		if !ok {
			return validationError("phoneNumber must be a string or null")
		}
		if err := a.checkPhone(ctx, n); err != nil {
			return err
		}
		if n == "" {
			return &APIError{400, "INVALID_PHONE_NUMBER", "Invalid phone number"}
		}
		if creating && !verified {
			u.PhoneNumberFields = &PhoneNumberFields{PhoneNumberVerified: &verified}
			return nil
		}
		if (f.PhoneNumber != nil && n != *f.PhoneNumber) || (f.PhoneNumber == nil && f.PhoneNumberVerified != nil && *f.PhoneNumberVerified) {
			// A verification flag belongs to the previous number.
			no := false
			f.PhoneNumberVerified = &no
		}
		f.PhoneNumber = &n
	}
	if hasFlag {
		if verified && (f.PhoneNumber == nil || *f.PhoneNumber == "") {
			return validationError("A phone number is required before it can be verified")
		}
		if flag == nil {
			f.PhoneNumberVerified = nil
		} else {
			f.PhoneNumberVerified = &verified
		}
	}
	u.PhoneNumberFields = &f
	return nil
}
