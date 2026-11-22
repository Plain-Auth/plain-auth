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
