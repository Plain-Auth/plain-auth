// Package authtest provides in-process fixtures for applications testing their
// Plain Auth integration. Import it from your tests.
package authtest

import (
	"crypto/rand"
	"strings"
	"time"

	auth "github.com/Plain-Auth/plain-auth"
	"github.com/Plain-Auth/plain-auth/plugins/organization"
)

// NewUser returns an unsaved, verified user. Set any fields before saving it.
func NewUser() auth.User {
	now := time.Now().UTC().Truncate(time.Millisecond)
	return auth.User{
		ID: rand.Text(), Name: "Test User",
		Email:         "test-" + strings.ToLower(rand.Text()[:8]) + "@example.com",
		EmailVerified: true, CreatedAt: now, UpdatedAt: now,
	}
}

// NewOrganization returns an unsaved organization. An empty name uses "Test Organization".
func NewOrganization(name string) organization.Organization {
	if name == "" {
		name = "Test Organization"
	}
	prefix := strings.Join(strings.Fields(strings.ToLower(name)), "-")
	return organization.Organization{
		ID: rand.Text(), Name: name,
		Slug:      prefix + "-" + strings.ToLower(rand.Text()[:4]),
		CreatedAt: time.Now().UTC().Truncate(time.Millisecond),
	}
}
