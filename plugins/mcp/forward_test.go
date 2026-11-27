package mcp

import (
	"context"
	"errors"
	"net/http"
	"reflect"
	"slices"
	"testing"
	"time"

	"github.com/Plain-Org/plain-auth/plugins/oauthprovider"
)

// called is the path of the last filled function that ran.
var called string

// sentinel implements the interfaces provider options take, so each filled
// interface field holds a value naming its path.
type sentinel struct{ path string }

func (sentinel) RoundTrip(*http.Request) (*http.Response, error) { return nil, errors.New("sentinel") }
func (sentinel) ReserveDPoPProof(context.Context, string, time.Time, time.Time) (bool, error) {
	return false, nil
}

// fill sets every settable field to a non-zero value, recursively. Each
// function records its field path when called, and each interface holds a
// sentinel naming it, so two fields of one type tell apart.
func fill(t *testing.T, v reflect.Value, path string, depth int) {
	if depth > 6 || !v.CanSet() {
		return
	}
	switch v.Kind() {
	case reflect.Bool:
		v.SetBool(true)
	case reflect.String:
		v.SetString("x")
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		v.SetInt(7)
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		v.SetUint(7)
	case reflect.Float32, reflect.Float64:
		v.SetFloat(7)
	case reflect.Slice:
		s := reflect.MakeSlice(v.Type(), 1, 1)
		fill(t, s.Index(0), path+"[0]", depth+1)
		v.Set(s)
	case reflect.Map:
		m := reflect.MakeMap(v.Type())
		key, value := reflect.New(v.Type().Key()).Elem(), reflect.New(v.Type().Elem()).Elem()
		fill(t, key, path+"{key}", depth+1)
		fill(t, value, path+"{value}", depth+1)
		m.SetMapIndex(key, value)
		v.Set(m)
	case reflect.Pointer:
		p := reflect.New(v.Type().Elem())
		fill(t, p.Elem(), path, depth+1)
		v.Set(p)
	case reflect.Func:
		typ := v.Type()
		v.Set(reflect.MakeFunc(typ, func([]reflect.Value) []reflect.Value {
			called = path
			out := make([]reflect.Value, typ.NumOut())
			for i := range out {
				out[i] = reflect.Zero(typ.Out(i))
			}
			return out
		}))
	case reflect.Interface:
		value := reflect.ValueOf(sentinel{path})
		if !value.Type().Implements(v.Type()) {
			t.Fatal("no sentinel implements", v.Type(), "at", path)
		}
		v.Set(value)
	case reflect.Struct:
		for i := range v.NumField() {
			fill(t, v.Field(i), path+"."+v.Type().Field(i).Name, depth+1)
		}
	}
}

// identity runs a filled function and returns the path it records.
func identity(f reflect.Value) string {
	called = ""
	args := make([]reflect.Value, f.Type().NumIn())
	for i := range args {
		args[i] = reflect.Zero(f.Type().In(i))
	}
	if f.Type().IsVariadic() {
		f.CallSlice(args)
	} else {
		f.Call(args)
	}
	return called
}

// same compares two option values: functions by the field they were filled
// for, pointers and interfaces by identity, and the rest by content.
func same(a, b reflect.Value) bool {
	switch a.Kind() {
	case reflect.Func:
		if a.IsNil() || b.IsNil() {
			return a.IsNil() == b.IsNil()
		}
		return identity(a) == identity(b)
	case reflect.Struct:
		for i := range a.NumField() {
			if a.Type().Field(i).IsExported() && !same(a.Field(i), b.Field(i)) {
				return false
			}
		}
		return true
	case reflect.Pointer:
		return a.Pointer() == b.Pointer()
	case reflect.Slice:
		if a.Len() != b.Len() {
			return false
		}
		for i := range a.Len() {
			if !same(a.Index(i), b.Index(i)) {
				return false
			}
		}
		return true
	case reflect.Map:
		if a.Len() != b.Len() {
			return false
		}
		for _, key := range a.MapKeys() {
			if !same(a.MapIndex(key), b.MapIndex(key)) {
				return false
			}
		}
		return true
	case reflect.Interface:
		if a.IsNil() || b.IsNil() {
			return a.IsNil() == b.IsNil()
		}
		return a.Interface() == b.Interface()
	}
	return reflect.DeepEqual(a.Interface(), b.Interface())
}

// Every provider option reaches the provider unchanged, except the MCP
// resource appended to Resources and Registration.DefaultResources after the
// host's own, so a provider field added later is forwarded too.
func TestProviderOptionsForwarded(t *testing.T) {
	var opts Options
	fill(t, reflect.ValueOf(&opts.Options).Elem(), "Options", 0)
	opts.Resource = "https://api.example.test/mcp"
	got := opts.provider()
	defaults := append(slices.Clone(opts.Registration.DefaultResources), opts.Resource)
	resources := append(slices.Clone(opts.Resources), oauthprovider.ResourceDefinition{Identifier: opts.Resource})
	if !same(reflect.ValueOf(got.Registration.DefaultResources), reflect.ValueOf(defaults)) || !same(reflect.ValueOf(got.Resources), reflect.ValueOf(resources)) {
		t.Fatal("the MCP resource was not appended after the host's", got.Registration.DefaultResources, len(got.Resources))
	}
	got.Registration.DefaultResources = opts.Registration.DefaultResources
	got.Resources = opts.Resources
	gotValue, wantValue := reflect.ValueOf(got), reflect.ValueOf(opts.Options)
	for i := range wantValue.NumField() {
		field := wantValue.Type().Field(i)
		if field.IsExported() && !same(gotValue.Field(i), wantValue.Field(i)) {
			t.Error("a provider option was not forwarded", field.Name)
		}
	}
	// Two filled functions of one type tell apart.
	if same(reflect.ValueOf(opts.Tokens.GenerateRefreshToken), reflect.ValueOf(opts.Tokens.GenerateOpaqueToken)) {
		t.Fatal("the check cannot tell two functions apart")
	}
	// A resource the host lists already is not added again.
	listed := Options{Resource: opts.Resource}
	listed.Registration.DefaultResources = []string{opts.Resource}
	listed.Resources = []oauthprovider.ResourceDefinition{{Identifier: opts.Resource, Policy: oauthprovider.ResourcePatch{DPoPBoundAccessTokensRequired: oauthprovider.Set(true)}}}
	if p := listed.provider(); len(p.Registration.DefaultResources) != 1 || len(p.Resources) != 1 || p.Resources[0].Policy.DPoPBoundAccessTokensRequired != listed.Resources[0].Policy.DPoPBoundAccessTokensRequired {
		t.Fatal("a listed resource was added again or replaced", p.Registration.DefaultResources, p.Resources)
	}
	// Two plugins built from one options value with spare capacity do not
	// share the appended slot.
	var base Options
	base.Registration.DefaultResources = append(make([]string, 0, 4), "urn:host")
	base.Resources = append(make([]oauthprovider.ResourceDefinition, 0, 4), oauthprovider.ResourceDefinition{Identifier: "urn:host"})
	first, second := base, base
	first.Resource, second.Resource = "https://a.example.test/mcp", "https://b.example.test/mcp"
	pa, pb := first.provider(), second.provider()
	if !slices.Equal(pa.Registration.DefaultResources, []string{"urn:host", first.Resource}) || !slices.Equal(pb.Registration.DefaultResources, []string{"urn:host", second.Resource}) ||
		pa.Resources[1].Identifier != first.Resource || pb.Resources[1].Identifier != second.Resource {
		t.Fatal("two plugins shared their appended resource", pa.Registration.DefaultResources, pb.Registration.DefaultResources)
	}
}

// The refresh reuse window defaults to 30 seconds; a negative value turns
// it off and any other is kept.
func TestRefreshReuseIntervalDefault(t *testing.T) {
	for given, want := range map[time.Duration]time.Duration{0: 30 * time.Second, -time.Second: 0, 10 * time.Second: 10 * time.Second} {
		var opts Options
		opts.Resource = "https://api.example.test/mcp"
		opts.Tokens.RefreshReuseInterval = given
		if got := opts.provider().Tokens.RefreshReuseInterval; got != want {
			t.Error("the refresh reuse window was wrong", given, got)
		}
	}
	// The provider accepts the default.
	var opts Options
	opts.Resource, opts.Scopes = "https://api.example.test/mcp", []string{"mcp:read"}
	opts.Authorization.LoginPage, opts.Authorization.ConsentPage = "/login", "/consent"
	if _, err := New(opts); err != nil {
		t.Fatal(err)
	}
}
