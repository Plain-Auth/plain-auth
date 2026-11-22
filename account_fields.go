package plainauth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"

	"github.com/Plain-Auth/plain-auth/internal/sessionfields"
	"golang.org/x/oauth2"
)

// AccountField declares an attribute of a provider or credential account.
type AccountField = sessionfields.Field

// AccountFieldRule customizes one declared account field. ValidateInput checks
// mapped provider values. TransformInput runs when a value is saved, including
// creation defaults. Both receive the normalized scalar and should be pure.
type AccountFieldRule struct {
	ValidateInput  func(any) error
	TransformInput func(any) (any, error)
}

// AccountFieldStore binds validated account declarations to one auth instance.
// Its returned store supplies defaults on account creation and lists only public fields.
type AccountFieldStore interface {
	WithAccountFields(map[string]AccountField, map[string]AccountFieldRule) (Store, error)
}

func configureAccountFields(opts *Options) error {
	if len(opts.AccountAdditionalFields) == 0 && len(opts.AccountFieldRules) == 0 {
		return nil
	}
	fields, err := sessionfields.NormalizeAccount(opts.AccountAdditionalFields)
	if err != nil {
		return err
	}
	for name := range opts.AccountFieldRules {
		if _, ok := fields[name]; !ok {
			return fmt.Errorf("auth: input rule for undeclared account field %q", name)
		}
	}
	store, ok := opts.Store.(AccountFieldStore)
	if !ok {
		return errors.New("auth: additional account fields require an AccountFieldStore")
	}
	opts.AccountAdditionalFields = fields
	opts.AccountFieldRules = maps.Clone(opts.AccountFieldRules)
	opts.Store, err = store.WithAccountFields(fields, opts.AccountFieldRules)
	return err
}

// OAuthAccountFieldInput distinguishes credentials verified by the provider flow
// from optional, unverified strings submitted by a native client.
type OAuthAccountFieldInput struct {
	// ExchangedToken exposes TokenType and provider-specific Extra values for code exchanges.
	ExchangedToken                        *oauth2.Token
	Profile                               OAuthProfile
	Tokens                                OAuthTokens
	ClientAccessToken, ClientRefreshToken string
}

// MappedAccountFields carries the declared provider values for an account write.
type MappedAccountFields struct{ values map[string]any }

// Get returns a value by logical name. A present nil explicitly clears a nullable field.
func (f *MappedAccountFields) Get(name string) (any, bool) {
	if f == nil {
		return nil, false
	}
	v, ok := f.values[name]
	return v, ok
}

func (a *Auth) mapAccountFields(ctx context.Context, provider OAuthProvider, input OAuthAccountFieldInput) (*MappedAccountFields, *APIError) {
	if provider.GetAccountFields == nil {
		return nil, nil
	}
	raw, err := provider.GetAccountFields(ctx, input)
	if err != nil {
		var api *APIError
		if errors.As(err, &api) {
			return nil, api
		}
		return nil, &APIError{500, "unable_to_get_user_info", "Could not map provider account fields"}
	}
	var values map[string]any
	for _, name := range sessionfields.Names(a.opts.AccountAdditionalFields) {
		f := a.opts.AccountAdditionalFields[name]
		rawValue, ok := raw[name]
		if !ok || f.ServerOnly {
			continue
		}
		v, err := f.Value(rawValue)
		if validate := a.opts.AccountFieldRules[name].ValidateInput; err == nil && validate != nil {
			err = validate(v)
		}
		if err != nil {
			return nil, &APIError{400, "VALIDATION_ERROR", "Invalid account field " + name}
		}
		if values == nil {
			values = make(map[string]any)
		}
		values[name] = v
	}
	if len(values) == 0 {
		return nil, nil
	}
	return &MappedAccountFields{values}, nil
}

type wireAccount LinkedAccount

func (a LinkedAccount) MarshalJSON() ([]byte, error) {
	base, err := json.Marshal(wireAccount(a))
	if err != nil || len(a.AdditionalFields) == 0 {
		return base, err
	}
	extras := make(map[string]any, len(a.AdditionalFields))
	for key, value := range a.AdditionalFields {
		if sessionfields.AccountNameOK(key) {
			extras[key] = value
		}
	}
	if len(extras) == 0 {
		return base, nil
	}
	data, err := json.Marshal(extras)
	if err != nil {
		return nil, err
	}
	base[len(base)-1] = ','
	return append(base, data[1:]...), nil
}

func (a *LinkedAccount) UnmarshalJSON(data []byte) error {
	var fixed wireAccount
	if err := json.Unmarshal(data, &fixed); err != nil {
		return err
	}
	var extras map[string]any
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := decoder.Decode(&extras); err != nil {
		return err
	}
	for name, value := range extras {
		if !sessionfields.AccountNameOK(name) {
			delete(extras, name)
		} else if n, ok := value.(json.Number); ok {
			if i, err := n.Int64(); err == nil {
				extras[name] = i
			}
		}
	}
	*a = LinkedAccount(fixed)
	if len(extras) > 0 {
		a.AdditionalFields = extras
	}
	return nil
}
