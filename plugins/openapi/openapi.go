package openapi

import (
	"bytes"
	"crypto/rand"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"html/template"
	"net/http"
	"path"
	"regexp"
	"slices"
	"sort"
	"strings"

	"github.com/Stonewrit/stonewrit-auth"
)

// Options configures the HTML reference page, independently of the JSON endpoint.
type Options struct {
	Path                    string
	DisableDefaultReference bool
	Theme                   string
	Nonce                   string
}

//go:embed reference.html
var referenceHTML string
var pageTemplate = template.Must(template.New("reference").Parse(referenceHTML))
var validNonce = regexp.MustCompile(`^[A-Za-z0-9+/_-]+={0,2}$`)
var themes = []string{"alternate", "default", "moon", "purple", "solarized", "bluePlanet", "saturn", "kepler", "mars", "deepSpace", "laserwave", "none"}

// New installs the public schema endpoint and, by default, its local HTML reference.
func New(options Options) (stonewrit.Plugin, error) {
	if options.Path == "" {
		options.Path = "/reference"
	}
	if !strings.HasPrefix(options.Path, "/") || path.Clean(options.Path) != options.Path || options.Path == "/" || options.Path == "/open-api/generate-schema" || strings.ContainsAny(options.Path, "%?#\\ \t\r\n") {
		return stonewrit.Plugin{}, errors.New("openapi: invalid reference path")
	}
	if options.Theme == "" {
		options.Theme = "default"
	}
	if !slices.Contains(themes, options.Theme) {
		return stonewrit.Plugin{}, errors.New("openapi: unknown theme")
	}
	if options.Nonce != "" && !validNonce.MatchString(options.Nonce) {
		return stonewrit.Plugin{}, errors.New("openapi: invalid CSP nonce")
	}
	p := stonewrit.Plugin{ID: "open-api", Endpoints: []stonewrit.Endpoint{{Method: http.MethodGet, Path: "/open-api/generate-schema", Handler: func(c stonewrit.EndpointContext) (any, error) { return Generate(c.Auth) }}}}
	if !options.DisableDefaultReference {
		p.Endpoints = append(p.Endpoints, stonewrit.Endpoint{Method: http.MethodGet, Path: options.Path, Handler: options.reference})
	}
	return p, nil
}

type pageOperation struct{ Method, Path, Detail string }

func (o Options) reference(c stonewrit.EndpointContext) (any, error) {
	doc, err := Generate(c.Auth)
	if err != nil {
		return nil, err
	}
	rows := []pageOperation{}
	for path, entry := range doc["paths"].(object) {
		for method, op := range entry.(object) {
			detail, err := json.MarshalIndent(op, "", "  ")
			if err != nil {
				return nil, err
			}
			rows = append(rows, pageOperation{strings.ToUpper(method), path, string(detail)})
		}
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Path == rows[j].Path {
			return rows[i].Method < rows[j].Method
		}
		return rows[i].Path < rows[j].Path
	})
	nonce := o.Nonce
	if nonce == "" {
		buf := make([]byte, 18)
		if _, err := rand.Read(buf); err != nil {
			return nil, err
		}
		nonce = base64.RawStdEncoding.EncodeToString(buf)
	}
	data := struct {
		Theme, Nonce, SchemaPath, Server string
		Operations                       []pageOperation
	}{o.Theme, nonce, strings.TrimRight(c.Auth.BasePath(), "/") + "/open-api/generate-schema", doc["servers"].([]object)[0]["url"].(string), rows}
	var out bytes.Buffer
	if err := pageTemplate.Execute(&out, data); err != nil {
		return nil, err
	}
	c.ResponseHeader.Set("Content-Security-Policy", "default-src 'none'; style-src 'nonce-"+nonce+"'; script-src 'nonce-"+nonce+"'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
	c.ResponseHeader.Set("Referrer-Policy", "no-referrer")
	return stonewrit.HTMLPage(out.String()), nil
}
