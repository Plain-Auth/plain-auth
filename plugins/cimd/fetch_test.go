package cimd

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"

	auth "github.com/Plain-Org/plain-auth"
)

type roundTrip func(*http.Request) (*http.Response, error)

func (f roundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func answer(status int, media, body string) *http.Response {
	h := http.Header{}
	if media != "" {
		h.Set("Content-Type", media)
	}
	return &http.Response{StatusCode: status, Header: h, Body: io.NopCloser(strings.NewReader(body)), ContentLength: -1}
}

// stalled is a body that blocks until its request's context ends.
type stalled struct{ ctx context.Context }

func (s stalled) Read([]byte) (int, error) { <-s.ctx.Done(); return 0, s.ctx.Err() }
func (stalled) Close() error               { return nil }

// A document fetch sends Accept and the cached validators, refuses a URL
// before any request, and answers each failure with its message and kind.
func TestFetchDocument(t *testing.T) {
	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, nil))
	valid := `{"client_id":"` + id + `","client_name":"App"}`
	var sent *http.Request
	respond := func(*http.Request) (*http.Response, error) { return answer(200, "application/json", valid), nil }
	client := &http.Client{Transport: roundTrip(func(r *http.Request) (*http.Response, error) { sent = r; return respond(r) }), CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	opts := Options{}
	got, err := opts.fetchDocument(t.Context(), client, id, `"v1"`, "Mon, 02 Jan 2006 15:04:05 GMT", logger)
	if err != nil || got.doc.ClientID != id || got.notModified {
		t.Fatal("a valid document was refused", err)
	}
	if sent.Header.Get("Accept") != "application/json" || sent.Header.Get("If-None-Match") != `"v1"` || sent.Header.Get("If-Modified-Since") == "" {
		t.Fatal("the request headers were wrong", sent.Header)
	}
	// A refused URL makes no request.
	sent = nil
	refuse := Options{AllowMetadataURL: func(context.Context, string) (bool, error) { return false, nil }}
	if err := refuse.checkURL(t.Context(), id); err == nil || err.Error() == "" || sent != nil {
		t.Fatal("a refused URL was fetched", err)
	}
	var problem *auth.OAuthError
	if err := refuse.checkURL(t.Context(), id); !errors.As(err, &problem) || problem.Description != "client_id URL is not permitted by the server's fetch policy" {
		t.Fatal("wrong refusal", err)
	}
	hookErr := errors.New("policy down")
	if err := (Options{AllowMetadataURL: func(context.Context, string) (bool, error) { return true, hookErr }}).checkURL(t.Context(), id); !errors.Is(err, hookErr) {
		t.Fatal("a policy error was not returned as is", err)
	}
	if err := opts.checkURL(t.Context(), "http://app.example.test/c"); !errors.As(err, &problem) || problem.Description != "client_id URL must use HTTPS" {
		t.Fatal("an invalid URL was not refused", err)
	}
	// Failures and their kinds.
	cases := map[string]struct {
		respond     func(*http.Request) (*http.Response, error)
		etag        string
		kind        failure
		status      int
		description string
	}{
		"refused": {func(*http.Request) (*http.Response, error) {
			return nil, &net.OpError{Op: "dial", Err: os.NewSyscallError("connect", syscall.ECONNREFUSED)}
		}, "", transientFailure, 400, networkFailure},
		"dns temporary": {func(*http.Request) (*http.Response, error) {
			return nil, &net.DNSError{Err: "server misbehaving", IsTemporary: true}
		}, "", transientFailure, 400, networkFailure},
		"dns not found": {func(*http.Request) (*http.Response, error) {
			return nil, &net.DNSError{Err: "no such host", IsNotFound: true}
		}, "", transportFailure, 400, networkFailure},
		"tls": {func(*http.Request) (*http.Response, error) {
			return nil, &net.OpError{Op: "remote error", Err: errors.New("tls: handshake failure")}
		}, "", transportFailure, 400, networkFailure},
		"transport": {func(*http.Request) (*http.Response, error) { return nil, errPrivate }, "", transportFailure, 400, networkFailure},
		"capacity":  {func(*http.Request) (*http.Response, error) { return nil, errLookupLimit }, "", capacityFailure, 429, "metadata DNS lookup capacity exceeded"},
		"304 bare":  {func(*http.Request) (*http.Response, error) { return answer(304, "", ""), nil }, "", terminalFailure, 400, "Metadata document returned 304 without a conditional validator"},
		"503":       {func(*http.Request) (*http.Response, error) { return answer(503, "application/json", ""), nil }, "", transientFailure, 400, "Metadata document fetch returned HTTP 503"},
		"404":       {func(*http.Request) (*http.Response, error) { return answer(404, "application/json", ""), nil }, "", terminalFailure, 400, "Metadata document fetch returned HTTP 404"},
		"302":       {func(*http.Request) (*http.Response, error) { return answer(302, "", ""), nil }, "", terminalFailure, 400, "Metadata document fetch returned HTTP 302"},
		"text/json": {func(*http.Request) (*http.Response, error) { return answer(200, "text/json", valid), nil }, "", terminalFailure, 400, `Metadata document must be JSON (got Content-Type "text/json")`},
		"quoted media": {func(*http.Request) (*http.Response, error) {
			return answer(200, `text/html; charset="utf-8"`, valid), nil
		}, "", terminalFailure, 400, `Metadata document must be JSON (got Content-Type "text/html; charset="utf-8"")`},
		"no media": {func(*http.Request) (*http.Response, error) { return answer(200, "", valid), nil }, "", terminalFailure, 400, `Metadata document must be JSON (got Content-Type "(none)")`},
		"streamed 6KB": {func(*http.Request) (*http.Response, error) {
			return answer(200, "application/json", strings.Repeat(" ", 6<<10)+valid), nil
		}, "", terminalFailure, 400, "Metadata document exceeds 5KB size limit"},
		"declared length": {func(*http.Request) (*http.Response, error) {
			r := answer(200, "application/json", valid)
			r.ContentLength = 9000
			return r, nil
		}, "", terminalFailure, 400, "Metadata document exceeds 5KB size limit"},
		"invalid JSON": {func(*http.Request) (*http.Response, error) { return answer(200, "application/json", "{"), nil }, "", terminalFailure, 400, "Metadata document is not valid JSON"},
		"invalid document": {func(*http.Request) (*http.Response, error) {
			return answer(200, "application/json", `{"client_id":"x"}`), nil
		}, "", terminalFailure, 400, `client_id "x" does not match the metadata document URL`},
	}
	for name, tc := range cases {
		respond = tc.respond
		_, err := opts.fetchDocument(t.Context(), client, id, tc.etag, "", logger)
		kind, ok := failureKind(err)
		if !ok || kind != tc.kind || !errors.As(err, &problem) || problem.Status != tc.status || problem.Description != tc.description {
			t.Error("wrong failure for", name, err, kind)
		}
	}
	// A leading byte order mark is dropped.
	respond = func(*http.Request) (*http.Response, error) {
		return answer(200, "application/json", "\xEF\xBB\xBF"+valid), nil
	}
	if _, err := opts.fetchDocument(t.Context(), client, id, "", "", logger); err != nil {
		t.Fatal("a document with a byte order mark was refused", err)
	}
	// Accepted media types, a conditional 304 and warnings.
	for _, media := range []string{"application/json;charset=utf-8", "application/client+json", "APPLICATION/JSON"} {
		respond = func(*http.Request) (*http.Response, error) { return answer(200, media, valid), nil }
		if _, err := opts.fetchDocument(t.Context(), client, id, "", "", logger); err != nil {
			t.Error("a JSON media type was refused", media, err)
		}
	}
	respond = func(*http.Request) (*http.Response, error) {
		r := answer(304, "", "")
		r.Header.Set("ETag", `"v2"`)
		return r, nil
	}
	if got, err := opts.fetchDocument(t.Context(), client, id, `"v1"`, "", logger); err != nil || !got.notModified || got.headers.ETag != `"v2"` {
		t.Fatal("a conditional 304 was not reported", got, err)
	}
	root := "https://app.example.test/"
	respond = func(*http.Request) (*http.Response, error) {
		return answer(200, "application/json", `{"client_id":"`+root+`"}`), nil
	}
	if _, err := opts.fetchDocument(t.Context(), client, root, "", "", logger); err != nil || !strings.Contains(logs.String(), "cimd metadata document warning: client_id URL path / is NOT RECOMMENDED") {
		t.Fatal("a warning was not logged", err, logs.String())
	}
	// A deadline while the body streams is a transient timeout.
	respond = func(r *http.Request) (*http.Response, error) {
		res := answer(200, "application/json", "")
		res.Body = stalled{r.Context()}
		return res, nil
	}
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
	defer cancel()
	_, err = opts.fetchDocument(ctx, client, id, "", "", logger)
	if kind, _ := failureKind(err); kind != transientFailure || !errors.As(err, &problem) || problem.Description != "Metadata document fetch timed out after 5000ms" {
		t.Fatal("a body deadline was not a transient timeout", err)
	}
	// So is a deadline before the headers arrive.
	respond = func(r *http.Request) (*http.Response, error) {
		<-r.Context().Done()
		return nil, r.Context().Err()
	}
	early, stop := context.WithTimeout(t.Context(), 20*time.Millisecond)
	defer stop()
	_, err = opts.fetchDocument(early, client, id, "", "", logger)
	if kind, _ := failureKind(err); kind != transientFailure || !errors.As(err, &problem) || problem.Description != "Metadata document fetch timed out after 5000ms" {
		t.Fatal("a header deadline was not a transient timeout", err)
	}
	// The fetch's own five-second bound applies without a caller deadline,
	// as a shared fetch has none.
	saved := fetchTimeout
	fetchTimeout = 20 * time.Millisecond
	defer func() { fetchTimeout = saved }()
	respond = func(r *http.Request) (*http.Response, error) {
		res := answer(200, "application/json", "")
		res.Body = stalled{r.Context()}
		return res, nil
	}
	_, err = opts.fetchDocument(context.WithoutCancel(t.Context()), client, id, "", "", logger)
	if kind, _ := failureKind(err); kind != transientFailure || !errors.As(err, &problem) || problem.Description != "Metadata document fetch timed out after 5000ms" {
		t.Fatal("the fetch's own bound did not apply", err)
	}
	// A timeout during the lookup says nothing about the host.
	respond = func(r *http.Request) (*http.Response, error) {
		<-r.Context().Done()
		return nil, lookupAborted{r.Context().Err()}
	}
	_, err = opts.fetchDocument(context.WithoutCancel(t.Context()), client, id, "", "", logger)
	if kind, _ := failureKind(err); kind != transportFailure || !errors.As(err, &problem) || problem.Description != "Metadata document fetch timed out after 5000ms" {
		t.Fatal("a lookup timeout was transient", err)
	}
	if _, ok := (Options{}).transport().(*transport); !ok {
		t.Fatal("a nil Transport did not select the pinned transport")
	}
}
