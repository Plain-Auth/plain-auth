package sso

import "testing"

// A ResolveUser decision must be complete to take effect.
func TestUserResolutionDecisions(t *testing.T) {
	if !(UserResolution{Action: ResolveContinue}).valid() {
		t.Fatal("a continue decision was refused")
	}
	if !(UserResolution{Action: ResolveLink, UserID: "u", Profile: "preserve"}).valid() || !(UserResolution{Action: ResolveLink, UserID: "u", Profile: "update"}).valid() {
		t.Fatal("a complete link decision was refused")
	}
	if (UserResolution{Action: ResolveLink, UserID: " ", Profile: "preserve"}).valid() {
		t.Fatal("a link without a user was accepted")
	}
	if (UserResolution{Action: ResolveLink, UserID: "u", Profile: "merge"}).valid() {
		t.Fatal("a link with an unknown profile mode was accepted")
	}
	if (UserResolution{Action: ResolveReject}).valid() {
		t.Fatal("a rejection without a code was accepted")
	}
	if (UserResolution{}).valid() {
		t.Fatal("an empty decision was accepted")
	}
}
