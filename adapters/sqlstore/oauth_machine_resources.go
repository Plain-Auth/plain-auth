package sqlstore

import (
	"context"
	"database/sql"

	op "github.com/Plain-Org/plain-auth/plugins/oauthprovider"
)

var _ op.ResourceMachineTokenStore = (*Store)(nil)

func (s *Store) WithMachineResources(ctx context.Context, clientID string, ids []string, prepare func(op.MachineClient, map[string]op.MachineResource) (*op.ResourceMachineTokenRecord, error)) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	// Use the registry's resource-before-client lock order. Row locks on links
	// serialize issuance with an unlink even if it bypasses the registry.
	found := make(map[string]op.MachineResource, len(ids))
	list, args := s.deviceTokenParameters(ids)
	if len(ids) > 0 {
		query := resourceSelect + ` WHERE "identifier" IN (` + list + `) ORDER BY "identifier"`
		rows, err := tx.QueryContext(ctx, s.readForUpdate(query), args...)
		if err != nil {
			return err
		}
		if err := collectMachineResources(rows, found); err != nil {
			return err
		}
	}
	client, err := scanMachineClient(tx.QueryRowContext(ctx, s.readForUpdate(machineClientSelect), clientID), clientID)
	if err != nil {
		return err
	}
	if len(found) > 0 {
		query := `SELECT "resourceId" FROM "oauthClientResource" WHERE "resourceId" IN (` + list + `) AND "clientId"=` + s.exactSQLValue("?") + ` ORDER BY "resourceId"`
		rows, err := tx.QueryContext(ctx, s.readForUpdate(query), append(args, clientID)...)
		if err != nil {
			return err
		}
		if err := collectMachineLinks(rows, found); err != nil {
			return err
		}
	}
	record, err := prepare(client, found)
	if err != nil {
		return err
	}
	if record != nil {
		if err := s.insertMachineToken(ctx, tx, clientID, *record); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func collectMachineResources(rows *sql.Rows, found map[string]op.MachineResource) error {
	defer rows.Close()
	for rows.Next() {
		resource, err := scanOAuthResource(rows)
		if err != nil {
			return err
		}
		found[resource.Identifier] = op.MachineResource{Resource: resource}
	}
	return rows.Err()
}

func collectMachineLinks(rows *sql.Rows, found map[string]op.MachineResource) error {
	defer rows.Close()
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return err
		}
		if row, ok := found[id]; ok {
			row.Linked = true
			found[id] = row
		}
	}
	return rows.Err()
}
