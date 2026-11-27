package publicnet

import "testing"

func TestPublicHost(t *testing.T) {
	for host, want := range map[string]bool{
		"app.example.test": true, "APP.Example.Test.": true, "my_app.example.test": true, "8.8.8.8": true, "2606:4700::1111": true, "bücher.example": true,
		"localhost": false, "app.localhost": false, "127.0.0.1": false, "::1": false, "10.0.0.1": false, "169.254.169.254": false, "192.0.2.1": false,
		"metadata.goog": false, "svc.internal": false, "printer.local": false, "intranet": false, "example.123": false, "example.0x1f": false, "": false, "exa mple.test": false,
	} {
		if got := PublicHost(host); got != want {
			t.Error("wrong public host answer", host, got)
		}
	}
	for host, want := range map[string]bool{"localhost": true, "LOCALHOST.": true, "a.localhost": true, "127.0.0.2": true, "::1": true, "::ffff:127.0.0.1": true, "example.test": false, "10.0.0.1": false} {
		if got := Loopback(host); got != want {
			t.Error("wrong loopback answer", host, got)
		}
	}
	for _, host := range []string{"a b.test", "a%41.test", "a|b.test", "a^b.test", "a\x7fb.test"} {
		if _, err := HostASCII(host); err == nil {
			t.Error("a forbidden host character was accepted", host)
		}
	}
	if ascii, err := HostASCII("Bücher.example"); err != nil || ascii != "xn--bcher-kva.example" {
		t.Error("an IDN host was not mapped", ascii, err)
	}
	for host, want := range map[string]bool{"example.123": true, "example.0X1f": true, "example.": false, "example..": true, "example.test": false, "10.0.0.1": false} {
		if got := AmbiguousHost(host); got != want {
			t.Error("wrong ambiguous host answer", host, got)
		}
	}
}
