// Package access evaluates resource and action permissions for application roles.
package access

import (
	"errors"
	"fmt"
	"slices"
)

// Statements lists the actions associated with each resource.
type Statements map[string][]string

// Match controls how a group of checks is combined. The zero value requires all.
type Match uint8

const (
	All Match = iota
	Any
)

// Requirement checks the named actions on a single resource.
type Requirement struct {
	Resource string
	Actions  []string
	Match    Match
}

// Control holds an application’s resource and action vocabulary.
type Control struct{ vocabulary Statements }

// Role holds an immutable selection of grants. A role is safe for concurrent use.
type Role struct{ grants Statements }

// ErrDenied identifies authorization failures, including empty requests.
var ErrDenied = errors.New("permission denied")

func clone(s Statements) Statements {
	result := make(Statements, len(s))
	for resource, actions := range s {
		result[resource] = slices.Clone(actions)
	}
	return result
}

// New defines which resources and actions can be assigned to roles.
func New(vocabulary Statements) Control {
	return Control{vocabulary: clone(vocabulary)}
}

// NewRole rejects grants outside the vocabulary. An empty grant list gives
// the role no actions on that resource.
func (c Control) NewRole(grants Statements) (Role, error) {
	for resource, actions := range grants {
		known, ok := c.vocabulary[resource]
		if !ok {
			return Role{}, fmt.Errorf("access: unknown resource %q", resource)
		}
		for _, action := range actions {
			if !slices.Contains(known, action) {
				return Role{}, fmt.Errorf("access: unknown action %q for resource %q", action, resource)
			}
		}
	}
	return Role{grants: clone(grants)}, nil
}

// Authorize checks the requirements in order. Each requirement has its own
// match mode. An empty request or a requirement with no actions never grants access.
func (r Role) Authorize(match Match, requirements ...Requirement) error {
	if len(requirements) == 0 || (match != All && match != Any) {
		return ErrDenied
	}
	for _, req := range requirements {
		ok := allows(r.grants[req.Resource], req.Actions, req.Match)
		if match == Any && ok {
			return nil
		}
		if match == All && !ok {
			return fmt.Errorf("%w for resource %q", ErrDenied, req.Resource)
		}
	}
	if match == Any {
		return ErrDenied
	}
	return nil
}

// AllowsAll checks a request in the resource-to-actions map form. It requires
// every requested resource to have at least one action, and every action to match.
func (s Statements) AllowsAll(request Statements) bool {
	for resource, actions := range request {
		if !allows(s[resource], actions, All) {
			return false
		}
	}
	return len(request) > 0
}

func allows(grants, actions []string, match Match) bool {
	if len(actions) == 0 || (match != All && match != Any) {
		return false
	}
	for _, action := range actions {
		has := slices.Contains(grants, action)
		if match == Any && has {
			return true
		}
		if match == All && !has {
			return false
		}
	}
	return match == All
}
