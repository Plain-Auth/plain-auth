# Role permissions

Use the `plugins/access` package to define permissions for your own handlers. Define the available actions once when the application starts. Create roles from that vocabulary, then select the role from the signed-in account or its current organization membership when authorizing a request.

```go
import "github.com/Plain-Org/plain-auth/plugins/access"

catalog := access.New(access.Statements{
    "project": {"read", "edit", "archive"},
    "report":  {"read", "publish"},
})
editor, err := catalog.NewRole(access.Statements{
    "project": {"read", "edit"},
    "report":  {"read"},
})
if err != nil {
    return err
}

err = editor.Authorize(access.All,
    access.Requirement{Resource: "project", Actions: []string{"edit"}},
    access.Requirement{
        Resource: "report", Actions: []string{"read", "publish"}, Match: access.Any,
    },
)
```

This request requires permission to edit projects and either read or publish reports. Use `access.Any` as the first argument when one matching resource is enough. If a check fails, `errors.Is(err, access.ErrDenied)` is true. A role definition containing an unknown action or resource fails at startup. The catalog and each role copy their inputs, so multiple handlers can safely share them.

For a simple resource-to-actions map, `grants.AllowsAll(request)` requires every requested action on every resource. An empty request or an empty action list grants no permission. The administration plugin applies this same check independently to each assigned role. [Administration](admin.md) · [Permission tests](../plugins/access/access_test.go)
