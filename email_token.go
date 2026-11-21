package betterauth

import (
	"context"
	"errors"
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

type verificationClaims struct {
	Email       string `json:"email"`
	UserID      string `json:"userId"`
	UpdateTo    string `json:"updateTo,omitempty"`
	RequestType string `json:"requestType,omitempty"`
	jwt.RegisteredClaims
}

func (a *Auth) emailVerificationToken(u User) (string, error) {
	now := a.now()
	claims := verificationClaims{Email: strings.ToLower(u.Email), UserID: u.ID, RegisteredClaims: jwt.RegisteredClaims{
		IssuedAt: jwt.NewNumericDate(now), ExpiresAt: jwt.NewNumericDate(now.Add(a.opts.EmailVerificationTokenTTL)),
	}}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	delete(token.Header, "typ")
	return token.SignedString([]byte(a.opts.Secret))
}

// VerifyEmail validates an HS256 link and verifies the address bound to the account.
func (a *Auth) VerifyEmail(ctx context.Context, raw string) error {
	s, err := a.accountStore()
	if err != nil {
		return err
	}
	var claims verificationClaims
	token, err := jwt.ParseWithClaims(raw, &claims, func(*jwt.Token) (any, error) { return []byte(a.opts.Secret), nil },
		jwt.WithValidMethods([]string{"HS256"}), jwt.WithExpirationRequired(), jwt.WithTimeFunc(a.now))
	if errors.Is(err, jwt.ErrTokenExpired) && !errors.Is(err, jwt.ErrTokenSignatureInvalid) {
		return &APIError{401, "TOKEN_EXPIRED", "Token expired"}
	}
	if err != nil || !token.Valid || claims.Email == "" || claims.UserID == "" || claims.UpdateTo != "" || claims.RequestType != "" {
		return &APIError{401, "INVALID_TOKEN", "Invalid token"}
	}
	err = s.VerifyAccountEmail(ctx, claims.UserID, claims.Email, a.now().UTC())
	if errors.Is(err, ErrNotFound) {
		return &APIError{401, "INVALID_TOKEN", "Invalid token"}
	}
	return err
}
