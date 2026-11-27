package oauthprovider

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"

	auth "github.com/Plain-Org/plain-auth"
	"golang.org/x/net/idna"
)

// RefreshIntrospectionStore reads the token, its issuing registration, user and
// session in one snapshot. Implementations return nil for missing, revoked or
// foreign tokens. A blank digest requests only a current registration check.
// A known opaque access token takes precedence when the request supplies no hint.
type RefreshIntrospectionStore interface {
	// InspectOpaqueMachineToken also reports whether an access token matched the digest,
	// including an inactive token or one owned by another client.
	InspectOpaqueMachineToken(ctx context.Context, clientID, digest string) (MachineClient, *MachineTokenRecord, bool, error)
	InspectRefreshToken(ctx context.Context, clientID, digest string) (MachineClient, *RefreshTokenRecord, error)
}

// RefreshTokenRecord carries the stored refresh grant and its current session state.
type RefreshTokenRecord struct {
	StoredToken, ClientID string
	IssuedAt, ExpiresAt   time.Time
	Scopes                []string
	// UserID is populated only for an existing user. SessionID and AuthorizationCodeID
	// describe the grant even when its linked session has ended.
	UserID, SessionID, AuthorizationCodeID string
	SessionExpiresAt                       time.Time
	SubjectType                            string
	RedirectURIs                           []string
	Confirmation                           map[string]any
}

func (opts Options) introspectRefresh(c auth.EndpointContext, req tokenAction, first MachineClient, store RefreshIntrospectionStore) (any, error) {
	ctx := c.Request.Context()
	digest, err := opts.Tokens.storedTokenDigest(ctx, req.token, StoredRefreshToken)
	if err != nil {
		return nil, err
	}
	current, record, err := store.InspectRefreshToken(ctx, req.client.id, digest)
	if err == nil {
		err = req.client.recheckClient(first, current)
	}
	if err != nil {
		return nil, tokenEndpointError(c.ResponseHeader, req.challenge, err)
	}
	now := time.Now()
	if digest == "" || record == nil || record.ClientID != current.ClientID || record.StoredToken != digest || record.ExpiresAt.Before(now) {
		return map[string]bool{"active": false}, nil
	}
	sessionLive := record.SessionID != "" && !record.SessionExpiresAt.Before(now)
	if !sessionLive && (record.SessionID != "" || record.AuthorizationCodeID != "") && !slices.Contains(record.Scopes, "offline_access") {
		return map[string]bool{"active": false}, nil
	}
	// The published issuer, as for opaque access tokens; another runtime
	// reports the configured spelling.
	claims := map[string]any{"active": true, "client_id": current.ClientID, "iss": c.Auth.OAuthIssuer(),
		"iat": record.IssuedAt.Unix(), "exp": record.ExpiresAt.Unix(), "token_type": "Bearer"}
	if record.Scopes != nil {
		claims["scope"] = strings.Join(record.Scopes, " ")
	}
	if sessionLive {
		claims["sid"] = record.SessionID
	}
	return opts.addTokenIdentity(claims, current.ClientID, record.UserID, record.SubjectType, record.RedirectURIs, record.Confirmation)
}

func pairwiseSubject(secret, userID string, redirects []string) (string, error) {
	if secret == "" {
		return "", errors.New("oauthprovider: pairwise secret required for stored pairwise client")
	}
	if len(redirects) == 0 {
		return "", errors.New("oauthprovider: missing pairwise sector redirect")
	}
	u, err := redirectURL(redirects[0])
	if err != nil {
		return "", errors.New("oauthprovider: invalid pairwise sector redirect")
	}
	sector, err := pairwiseSector(u.Hostname(), u.Port(), u.Scheme)
	if err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(sector + "." + userID))
	return base64.StdEncoding.EncodeToString(mac.Sum(nil)), nil
}

// The sector is the serialized URL host, including a non-default port.
func pairwiseSector(name, port, scheme string) (string, error) {
	if ip, err := netip.ParseAddr(name); err == nil && ip.Is6() {
		if ip.Zone() != "" {
			return "", errors.New("oauthprovider: invalid pairwise sector zone")
		}
		name = "[" + ip.String() + "]"
		if ip.Is4In6() {
			// URL hosts serialize mapped IPv4 addresses using hexadecimal IPv6 pieces.
			v := ip.As4()
			name = fmt.Sprintf("[::ffff:%x:%x]", binary.BigEndian.Uint16(v[:2]), binary.BigEndian.Uint16(v[2:]))
		}
	} else if name != "" {
		ascii, err := idna.Lookup.ToASCII(name)
		if err != nil {
			return "", errors.New("oauthprovider: invalid pairwise sector host")
		}
		name = strings.ToLower(ascii)
	}
	if port != "" {
		n, err := strconv.ParseUint(port, 10, 16)
		if err != nil {
			return "", errors.New("oauthprovider: invalid pairwise sector port")
		}
		if !(scheme == "https" && n == 443 || scheme == "http" && n == 80) {
			name += ":" + strconv.FormatUint(n, 10)
		}
	}
	return name, nil
}
