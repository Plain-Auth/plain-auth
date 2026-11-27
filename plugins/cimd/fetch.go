package cimd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"time"

	auth "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/plugins/oauthprovider"
)

const (
	fetchTimeout     = 5 * time.Second
	maxDocumentBytes = 5 << 10
	networkFailure   = "Failed to fetch metadata document (network error or redirect blocked)"
)

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

// checkURL refuses a client ID URL before it is fetched: one that is not a
// valid metadata document URL, or one the host refuses.
func (o Options) checkURL(ctx context.Context, clientIDURL string) error {
	if err := ValidateClientIDURL(clientIDURL); err != nil {
		return fetchFailure(terminalFailure, err.Error())
	}
	if o.AllowMetadataURL != nil {
		allowed, err := o.AllowMetadataURL(ctx, clientIDURL)
		if err != nil {
			return err
		}
		if !allowed {
			return fetchFailure(terminalFailure, "client_id URL is not permitted by the server's fetch policy")
		}
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
	timeout := fmt.Sprintf("Metadata document fetch timed out after %dms", fetchTimeout.Milliseconds())
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
		switch {
		case errors.Is(err, errLookupLimit):
			return fetchedDocument{}, fetchError{&auth.OAuthError{Status: 429, Code: "temporarily_unavailable", Description: "metadata DNS lookup capacity exceeded"}, capacityFailure}
		case timedOut():
			return fetchedDocument{}, fetchFailure(transientFailure, timeout)
		case transientNetwork(err):
			return fetchedDocument{}, fetchFailure(transientFailure, networkFailure)
		}
		return fetchedDocument{}, fetchFailure(transportFailure, networkFailure)
	}
	defer res.Body.Close()
	headers := cacheHeaders{res.Header.Get("Cache-Control"), res.Header.Get("Vary"), res.Header.Get("Expires"), res.Header.Get("Date"),
		res.Header.Get("Age"), res.Header.Get("ETag"), res.Header.Get("Last-Modified")}
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
		return fetchedDocument{}, fetchFailure(terminalFailure, fmt.Sprintf("Metadata document must be JSON (got Content-Type %q)", media))
	}
	tooLarge := fetchFailure(terminalFailure, "Metadata document exceeds 5KB size limit")
	if res.ContentLength > maxDocumentBytes {
		return fetchedDocument{}, tooLarge
	}
	body, err := io.ReadAll(io.LimitReader(res.Body, maxDocumentBytes+1))
	switch {
	case err != nil && timedOut():
		return fetchedDocument{}, fetchFailure(transientFailure, timeout)
	case err != nil && transientNetwork(err):
		return fetchedDocument{}, fetchFailure(transientFailure, networkFailure)
	case err != nil:
		return fetchedDocument{}, fetchFailure(transportFailure, networkFailure)
	case len(body) > maxDocumentBytes:
		return fetchedDocument{}, tooLarge
	case !json.Valid(body):
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

// transientNetwork reports a failure that may pass on retry: a timeout or a
// connection failure, where another runtime reads Node error codes.
func transientNetwork(err error) bool {
	var netErr net.Error
	var op *net.OpError
	return errors.As(err, &netErr) && netErr.Timeout() || errors.As(err, &op) || errors.Is(err, io.ErrUnexpectedEOF)
}
