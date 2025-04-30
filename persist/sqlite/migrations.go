package sqlite

import (
	"go.uber.org/zap"
)

// migrations is a list of functions that are run to migrate the database from
// one version to the next. Migrations are used to update existing databases to
// match the schema in init.sql.
var migrations = []func(tx *txn, log *zap.Logger) error{
	// migration 1: add an index on the date created column of the seeds table
	// to speed up sorting
	func(tx *txn, _ *zap.Logger) error {
		_, err := tx.Exec(`CREATE INDEX seeds_date_created_idx ON seeds (date_created ASC);`)
		return err
	},
}
