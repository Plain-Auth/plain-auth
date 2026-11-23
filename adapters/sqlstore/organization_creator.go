package sqlstore

import (
	"context"
	"database/sql"
	"errors"

	auth "github.com/Plain-Org/plain-auth"
)

// errUserNotFound answers trusted calls that name an account that does not exist.
var errUserNotFound = &auth.APIError{Status: 400, Code: "USER_NOT_FOUND", Message: "User not found"}

// OrganizationCreator reads the account a trusted creation names, so the
// organization plugin can pass it to the host's creation callbacks.
func (s *Store) OrganizationCreator(ctx context.Context, userID string) (auth.User, error) {
	var user auth.User
	q := `SELECT ` + userColumns + ` FROM "user" u WHERE u."id"=` + s.exactSQLValue("?")
	err := s.db.QueryRowContext(ctx, s.bind(q), userID).Scan(userFields(&user)...)
	if errors.Is(err, sql.ErrNoRows) || err == nil && user.ID != userID {
		return auth.User{}, errUserNotFound
	}
	return user, err
}
