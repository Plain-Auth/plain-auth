// Package siwe authenticates externally owned Ethereum accounts using signed
// EIP-4361 messages and one-use server challenges.
package siwe

import (
	"encoding/hex"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"golang.org/x/crypto/sha3"

	"github.com/Plain-Org/plain-auth/internal/httporigin"
)

type message struct {
	address    string
	chain      int64
	nonce      string
	expiration time.Time
}

func validNonce(s string) bool {
	if len(s) < 8 || len(s) > 250 {
		return false
	}
	for _, c := range s {
		if !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9') {
			return false
		}
	}
	return true
}

func nonceFrom(lines []string) string {
	var nonce string
	for _, l := range lines {
		if n, ok := strings.CutPrefix(l, "Nonce: "); ok {
			if nonce != "" || !validNonce(n) {
				return ""
			}
			nonce = n
		}
	}
	return nonce
}

// canonicalOrigin rejects userinfo, path fragments in authorities, and origins
// the signed message could confuse with another relying party.
func canonicalOrigin(raw string) (scheme, authority string, ok bool) {
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	u, err := url.Parse(raw)
	// A non-ASCII host could fold into the configured ASCII domain while a
	// wallet shows its different Punycode domain, so it is refused.
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.User != nil || u.Hostname() == "" || !httporigin.ASCIIOnly(u.Host) || strings.ContainsAny(u.Host, "*%\\") || u.Path != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return "", "", false
	}
	return u.Scheme, httporigin.ASCIILower(u.Host), true
}

func checksumAddress(s string) (string, bool) {
	if len(s) != 42 || !strings.HasPrefix(s, "0x") {
		return "", false
	}
	lower := strings.ToLower(s[2:])
	if _, err := hex.DecodeString(lower); err != nil {
		return "", false
	}
	h := sha3.NewLegacyKeccak256()
	h.Write([]byte(lower))
	sum := h.Sum(nil)
	out := []byte(lower)
	for i, c := range out {
		n := sum[i/2] >> 4
		if i%2 != 0 {
			n = sum[i/2] & 15
		}
		if c >= 'a' && c <= 'f' && n >= 8 {
			out[i] = c - 'a' + 'A'
		}
	}
	checksum := string(out)
	// Lowercase addresses are widely used. A mixed-case address carries
	// an EIP-55 checksum and must have the correct capitalization.
	if input := s[2:]; input != lower && input != strings.ToUpper(lower) && input != checksum {
		return "", false
	}
	return "0x" + checksum, true
}

func parseMessage(lines []string, scheme, domain string, now time.Time) (message, error) {
	var out message
	if len(lines) < 8 || lines[2] != "" {
		return out, errMismatch
	}
	header, ok := strings.CutSuffix(lines[0], " wants you to sign in with your Ethereum account:")
	if !ok {
		return out, errMismatch
	}
	if !strings.Contains(header, "://") {
		header = scheme + "://" + header
	}
	hScheme, host, ok := canonicalOrigin(header)
	if !ok || host != domain || hScheme != scheme {
		return out, errMismatch
	}
	out.address, ok = checksumAddress(lines[1])
	if !ok {
		return out, errMismatch
	}
	// An optional statement is one line. The labeled fields must follow in
	// canonical order, so text inside a statement or resource cannot override them.
	i := 3
	if !strings.HasPrefix(lines[i], "URI: ") {
		if lines[i] != "" {
			i++
		}
		if i >= len(lines) || lines[i] != "" {
			return out, errMismatch
		}
		i++
	}
	next := func(label string) (string, bool) {
		if i >= len(lines) {
			return "", false
		}
		v, ok := strings.CutPrefix(lines[i], label+": ")
		if !ok {
			return "", false
		}
		i++
		return v, true
	}
	uri, ok := next("URI")
	u, err := url.ParseRequestURI(uri)
	if !ok || err != nil || u.Scheme != scheme || u.User != nil || !httporigin.ASCIIOnly(u.Host) || httporigin.ASCIILower(u.Host) != domain {
		return out, errMismatch
	}
	if v, ok := next("Version"); !ok || v != "1" {
		return out, errMismatch
	}
	chain, ok := next("Chain ID")
	out.chain, err = strconv.ParseInt(chain, 10, 64)
	if !ok || err != nil || out.chain <= 0 || out.chain > 1<<31-1 || strconv.FormatInt(out.chain, 10) != chain {
		return out, errMismatch
	}
	out.nonce, ok = next("Nonce")
	if !ok || !validNonce(out.nonce) {
		return out, errMismatch
	}
	issued, ok := next("Issued At")
	at, err := time.Parse(time.RFC3339Nano, issued)
	if !ok || err != nil || at.After(now.Add(time.Minute)) {
		return out, errMismatch
	}
	if raw, ok := next("Expiration Time"); ok {
		end, err := time.Parse(time.RFC3339Nano, raw)
		if err != nil {
			return out, errMismatch
		}
		out.expiration = end
		if !now.Before(end) {
			return out, errExpired
		}
	}
	if raw, ok := next("Not Before"); ok {
		begin, err := time.Parse(time.RFC3339Nano, raw)
		if err != nil {
			return out, errMismatch
		}
		if now.Before(begin) {
			return out, errEarly
		}
	}
	next("Request ID")
	if i < len(lines) && lines[i] == "Resources:" {
		i++
		for ; i < len(lines); i++ {
			raw, ok := strings.CutPrefix(lines[i], "- ")
			u, err := url.Parse(raw)
			if !ok || err != nil || !u.IsAbs() {
				return out, errMismatch
			}
		}
	}
	if i != len(lines) {
		return out, errMismatch
	}
	return out, nil
}

func validSignature(text, signature, address string) bool {
	if len(signature) != 132 || !strings.HasPrefix(signature, "0x") {
		return false
	}
	raw, err := hex.DecodeString(signature[2:])
	if err != nil {
		return false
	}
	v := raw[64]
	if v == 0 || v == 1 {
		v += 27
	}
	if v != 27 && v != 28 {
		return false
	}
	compact := make([]byte, 65)
	compact[0] = v
	copy(compact[1:], raw[:64])
	h := sha3.NewLegacyKeccak256()
	h.Write([]byte("\x19Ethereum Signed Message:\n" + strconv.Itoa(len(text))))
	h.Write([]byte(text))
	key, _, err := ecdsa.RecoverCompact(compact, h.Sum(nil))
	if err != nil {
		return false
	}
	h.Reset()
	h.Write(key.SerializeUncompressed()[1:])
	sum := h.Sum(nil)
	return strings.EqualFold(address, "0x"+hex.EncodeToString(sum[12:]))
}
