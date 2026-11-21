package onetap

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

func localPath(path string) bool {
	u, err := url.ParseRequestURI(path)
	if err != nil || u.IsAbs() || u.Host != "" || !strings.HasPrefix(path, "/") {
		return false
	}
	decoded, err := url.PathUnescape(u.EscapedPath())
	return err == nil && !strings.HasPrefix(decoded, "//") && !strings.ContainsAny(decoded, "\\\r\n") && !strings.Contains(path, "#")
}

// RedirectHandler receives the credential form sent by Google Identity Services.
// Mount it on the application origin. Its first-party page posts to the normal
// nonce-bound callback, where the browser can send its Strict challenge cookie.
func RedirectHandler(authPath, successPath string) (http.Handler, error) {
	if !localPath(authPath) || strings.Contains(authPath, "?") || !localPath(successPath) {
		return nil, errors.New("onetap: expected local mount and destination paths")
	}
	const relay = `<!doctype html><meta charset="utf-8"><title>Google sign-in</title><p id="status">Completing sign-in…</p><script nonce="%s">
const data=%s;
fetch(data.endpoint,{method:"POST",mode:"same-origin",credentials:"same-origin",redirect:"error",headers:{"Content-Type":"application/json"},body:JSON.stringify({idToken:data.credential,callbackURL:data.destination})})
.then(response=>{if(!response.ok)throw Error(); location.replace(data.destination)})
.catch(()=>{document.getElementById("status").textContent="Sign-in could not be completed."});
</script>`
	endpoint := strings.TrimRight(authPath, "/") + "/one-tap/callback"
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", "POST")
			w.WriteHeader(405)
			return
		}
		// Google may omit Origin on a cross-site POST. Always require the
		// independent GIS cookie and matching posted value.
		if from := r.Header.Get("Origin"); from != "" && from != "null" && from != "https://accounts.google.com" {
			http.Error(w, "Invalid sign-in origin", 403)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 72<<10)
		if err := r.ParseForm(); err != nil {
			http.Error(w, "Invalid sign-in form", 400)
			return
		}
		csrf := r.PostForm["g_csrf_token"]
		values := r.PostForm["credential"]
		cookies := r.CookiesNamed("g_csrf_token")
		if len(csrf) != 1 || len(cookies) != 1 || csrf[0] == "" || subtle.ConstantTimeCompare([]byte(csrf[0]), []byte(cookies[0].Value)) != 1 {
			http.Error(w, "Invalid verification cookie", 403)
			return
		}
		if len(values) != 1 || values[0] == "" || len(values[0]) > 64<<10 {
			http.Error(w, "Invalid credential", 400)
			return
		}
		encoded, err := json.Marshal(map[string]string{"endpoint": endpoint, "credential": values[0], "destination": successPath})
		if err != nil {
			http.Error(w, "Invalid sign-in form", 400)
			return
		}
		nonce := rand.Text()
		w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'nonce-"+nonce+"'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprintf(w, relay, nonce, encoded)
	}), nil
}
