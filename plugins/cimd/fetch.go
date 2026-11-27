package cimd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	auth "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/internal/publicnet"
	"github.com/Plain-Org/plain-auth/plugins/oauthprovider"
)

const (
	maxDocumentBytes = 5 << 10
	networkFailure   = "Failed to fetch metadata document (network error or redirect blocked)"
	timeoutFailure   = "Metadata document fetch timed out after 5000ms"
)

// fetchTimeout bounds a document fetch, headers and body; tests shorten it.
var fetchTimeout = 5 * time.Second

var jsonMedia = regexp.MustCompile(`(?i)^application/(?:[-\w.]+\+)?json\s*(?:;|$)`)

// failure classifies a failed fetch for stale serving: a transient failure
// may pass on retry, a transport failure retrieved nothing, a capacity
// refusal says nothing about the document, and a terminal one is final.
type failure int

const (
	terminalFailure failure = iota
	transientFailure
	transportFailure
	capacityFailure
)

// fetchError is a failed fetch: the OAuth error to answer with and its kind.
type fetchError struct {
	*auth.OAuthError
	kind failure
}

func (e fetchError) Unwrap() error { return e.OAuthError }

func fetchFailure(kind failure, description string) error {
	return fetchError{&auth.OAuthError{Status: 400, Code: "invalid_client", Description: description}, kind}
}

func failureKind(err error) (failure, bool) {
	var f fetchError
	if errors.As(err, &f) {
		return f.kind, true
	}
	return 0, false
}

// cacheHeaders are a document response's caching headers.
type cacheHeaders struct {
	CacheControl, Vary, Expires, Date, Age, ETag, LastModified string
}

// fetchedDocument is a validated document, or a not-modified answer to a
// conditional fetch, with its caching headers.
type fetchedDocument struct {
	doc         oauthprovider.ClientMetadataDocument
	notModified bool
	headers     cacheHeaders
}

// policyError is an error the host's URL policy returned, which the
// request answers with as is and which stops stale serving like a refusal.
type policyError struct{ err error }

func (e policyError) Error() string { return e.err.Error() }
func (e policyError) Unwrap() error { return e.err }

// checkURL refuses a client ID URL before it joins or starts a fetch: one
// that is not a valid metadata document URL, or one the host refuses. A
// request that ended during the host's check records nothing.
func (o Options) checkURL(ctx context.Context, clientIDURL string) error {
	if err := ValidateClientIDURL(clientIDURL); err != nil {
		return fetchFailure(terminalFailure, err.Error())
	}
	if o.AllowMetadataURL == nil {
		return nil
	}
	allowed, err := o.AllowMetadataURL(ctx, clientIDURL)
	switch {
	case err != nil && ctx.Err() != nil:
		return err
	case err != nil:
		return policyError{err}
	case !allowed:
		return fetchFailure(terminalFailure, "client_id URL is not permitted by the server's fetch policy")
	}
	return nil
}

// fetchDocument fetches and validates one metadata document, as another
// runtime's fetchClientMetadataDocument does: JSON of at most 5 KB, no
// redirects, five seconds for headers and body, and conditional validators
// only from a document validated before.
func (o Options) fetchDocument(ctx context.Context, client *http.Client, clientIDURL, etag, lastModified string, logger *slog.Logger) (fetchedDocument, error) {
	ctx, cancel := context.WithTimeout(ctx, fetchTimeout)
	defer cancel()
	timedOut := func() bool { return errors.Is(ctx.Err(), context.DeadlineExceeded) }
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, clientIDURL, nil)
	if err != nil {
		return fetchedDocument{}, fetchFailure(terminalFailure, networkFailure)
	}
	req.Header.Set("Accept", "application/json")
	if etag != "" {
		req.Header.Set("If-None-Match", etag)
	}
	if lastModified != "" {
		req.Header.Set("If-Modified-Since", lastModified)
	}
	res, err := client.Do(req)
	if err != nil {
		var aborted lookupAborted
		switch {
		case errors.Is(err, oauthprovider.ErrFetchCapacity):
			return fetchedDocument{}, fetchError{&auth.OAuthError{Status: 429, Code: "temporarily_unavailable", Description: "metadata DNS lookup capacity exceeded"}, capacityFailure}
		case errors.As(err, &aborted) && timedOut():
			// A timeout during the lookup says nothing about the host. A
			// custom transport's timeouts count as reaching the host, where
			// another runtime asks such a transport to report it.
			return fetchedDocument{}, fetchFailure(transportFailure, timeoutFailure)
		case timedOut():
			return fetchedDocument{}, fetchFailure(transientFailure, timeoutFailure)
		case publicnet.Transient(err):
			return fetchedDocument{}, fetchFailure(transientFailure, networkFailure)
		}
		return fetchedDocument{}, fetchFailure(transportFailure, networkFailure)
	}
	defer res.Body.Close()
	// Repeated list headers read as their lines joined; for the others the
	// first line counts, as another runtime's Node transport reads them.
	joined := func(name string) string { return strings.Join(res.Header.Values(name), ", ") }
	headers := cacheHeaders{joined("Cache-Control"), joined("Vary"), res.Header.Get("Expires"), joined("Date"), res.Header.Get("Age"),
		res.Header.Get("ETag"), res.Header.Get("Last-Modified")}
	if res.StatusCode == http.StatusNotModified {
		if etag == "" && lastModified == "" {
			return fetchedDocument{}, fetchFailure(terminalFailure, "Metadata document returned 304 without a conditional validator")
		}
		return fetchedDocument{notModified: true, headers: headers}, nil
	}
	if res.StatusCode != http.StatusOK {
		kind := terminalFailure
		switch res.StatusCode {
		case 500, 502, 503, 504:
			kind = transientFailure
		}
		return fetchedDocument{}, fetchFailure(kind, "Metadata document fetch returned HTTP "+strconv.Itoa(res.StatusCode))
	}
	if media := res.Header.Get("Content-Type"); !jsonMedia.MatchString(media) {
		if media == "" {
			media = "(none)"
		}
		return fetchedDocument{}, fetchFailure(terminalFailure, `Metadata document must be JSON (got Content-Type "`+media+`")`)
	}
	tooLarge := fetchFailure(terminalFailure, "Metadata document exceeds 5KB size limit")
	if res.ContentLength > maxDocumentBytes {
		return fetchedDocument{}, tooLarge
	}
	body, err := io.ReadAll(io.LimitReader(res.Body, maxDocumentBytes+1))
	switch {
	case err != nil && timedOut():
		return fetchedDocument{}, fetchFailure(transientFailure, timeoutFailure)
	case err != nil && publicnet.Transient(err):
		return fetchedDocument{}, fetchFailure(transientFailure, networkFailure)
	case err != nil:
		return fetchedDocument{}, fetchFailure(transportFailure, networkFailure)
	case len(body) > maxDocumentBytes:
		return fetchedDocument{}, tooLarge
	}
	// A UTF-8 byte order mark counts toward the size and is then dropped, as
	// a browser's text decoder does.
	body = bytes.TrimPrefix(body, []byte("\xEF\xBB\xBF"))
	if !json.Valid(body) {
		return fetchedDocument{}, fetchFailure(terminalFailure, "Metadata document is not valid JSON")
	}
	doc, warnings, err := ValidateMetadata(clientIDURL, body, ValidationOptions{OriginBoundFields: o.OriginBoundFields, Profile: o.Profile})
	if err != nil {
		return fetchedDocument{}, fetchFailure(terminalFailure, err.Error())
	}
	for _, warning := range warnings {
		logger.WarnContext(ctx, "cimd metadata document warning: "+warning)
	}
	return fetchedDocument{doc: doc, headers: headers}, nil
}
