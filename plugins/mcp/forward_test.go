package mcp

import (
	"reflect"
	"slices"
	"testing"

	"github.com/Plain-Org/plain-auth/plugins/oauthprovider"
)

// fill sets every settable field to a non-zero value, recursively.
func fill(v reflect.Value, depth int) {
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
		fill(s.Index(0), depth+1)
		v.Set(s)
	case reflect.Map:
		m := reflect.MakeMap(v.Type())
		key, value := reflect.New(v.Type().Key()).Elem(), reflect.New(v.Type().Elem()).Elem()
		fill(key, depth+1)
		fill(value, depth+1)
		m.SetMapIndex(key, value)
		v.Set(m)
	case reflect.Pointer:
		p := reflect.New(v.Type().Elem())
		fill(p.Elem(), depth+1)
		v.Set(p)
	case reflect.Func:
		v.Set(reflect.MakeFunc(v.Type(), func([]reflect.Value) []reflect.Value { return nil }))
	case reflect.Struct:
		for i := range v.NumField() {
			fill(v.Field(i), depth+1)
		}
	}
}

// same compares two option values, functions by code pointer.
func same(a, b reflect.Value) bool {
	switch a.Kind() {
	case reflect.Func:
		return a.Pointer() == b.Pointer()
	case reflect.Struct:
		for i := range a.NumField() {
			if a.Type().Field(i).IsExported() && !same(a.Field(i), b.Field(i)) {
				return false
			}
		}
		return true
	case reflect.Pointer:
		if a.IsNil() || b.IsNil() {
			return a.IsNil() == b.IsNil()
		}
		return same(a.Elem(), b.Elem())
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
		return a.IsNil() == b.IsNil()
	}
	return reflect.DeepEqual(a.Interface(), b.Interface())
}

// Every provider option reaches the provider unchanged, except the MCP
// resource added to Resources and Registration.DefaultResources, so a
// provider field added later is forwarded too.
func TestProviderOptionsForwarded(t *testing.T) {
	var opts Options
	fill(reflect.ValueOf(&opts.Options).Elem(), 0)
	opts.Resource = "https://api.example.test/mcp"
	got := opts.provider()
	if !slices.Contains(got.Registration.DefaultResources, opts.Resource) || !slices.ContainsFunc(got.Resources, func(d oauthprovider.ResourceDefinition) bool { return d.Identifier == opts.Resource }) {
		t.Fatal("the MCP resource was not added")
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
}
