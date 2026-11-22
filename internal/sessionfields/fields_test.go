package sessionfields

import (
	"encoding/json"
	"testing"
)

func TestExactPortableNumbers(t *testing.T) {
	f := Field{Type: Number}
	for raw, want := range map[string]int64{"0": 0, "-0.00e1000000": 0, "0.1e1": 1, "12.3400e2": 1234, "-2147483648": -2147483648, "21474836470e-1": 2147483647} {
		got, err := f.Value(json.Number(raw))
		if err != nil || got != want {
			t.Errorf("%s: got %v, %v; want %v", raw, got, err, want)
		}
	}
	for _, raw := range []string{"1.00000000000000001", "2147483648", "-2147483649", "1e9999999999999999999999999", "1e-9999999999999999999999999", "0.001", "not-a-number"} {
		if _, err := f.Value(json.Number(raw)); err == nil {
			t.Errorf("accepted %q", raw)
		}
	}
}

func TestDateValue(t *testing.T) {
	f := Field{Type: Date}
	for _, raw := range []string{"2024-02-29T12:02:03.120456+01:00", "2024-02-29t11:02:03.120z"} {
		got, err := f.PublicValue(raw)
		if err != nil || got != "2024-02-29T11:02:03.120Z" {
			t.Errorf("normalized date %v, %v", got, err)
		}
	}
	for _, raw := range []any{false, 0, "2025-02-29T12:02:00Z", "2024-02-29", "2024-02-29T12:02:00", "2024-02-29T12:02:00+13:60", "2024-02-29T12:02:00+24:00", "0001-01-01T00:00:00+05:00"} {
		if _, err := f.Value(raw); err == nil {
			t.Errorf("accepted invalid date %v", raw)
		}
	}
}

func TestComputedDefaultSignaturesAndValidation(t *testing.T) {
	var nilCallback func() string
	for _, invalid := range []any{nilCallback, func(int) string { return "" }, func() {}, func() (int, int) { return 0, 0 }} {
		if _, err := NormalizeUser(map[string]Field{"example": {Type: String, Default: invalid}}); err == nil {
			t.Fatal("accepted invalid callback signature")
		}
	}
	for _, generate := range []any{func() int { return 3 }, func() any { panic("private application detail") }} {
		fields, err := Normalize(map[string]Field{"value": {Type: String, Required: true, Default: generate}})
		if err != nil {
			t.Fatal(err)
		}
		f := fields["value"]
		if f.StaticDefault() != nil {
			t.Fatal("callback offered as a SQL default")
		}
		if _, err := f.CreationDefault(); err == nil || err.Error() == "private application detail" {
			t.Fatalf("invalid callback returned %v", err)
		}
	}
}
