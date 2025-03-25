package sqlite

import (
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/mattn/go-sqlite3"
	"go.uber.org/zap"
	"lukechampine.com/frand"
)

const (
	maxBackoff    = 15 * time.Second
	backoffFactor = 1.8
)

type (
	// A Store is a persistent store that uses a SQL database as its backend.
	Store struct {
		maxRetryAttempts int

		db  *sql.DB
		log *zap.Logger
	}
)

// Close closes the underlying database.
func (s *Store) Close() error {
	return s.db.Close()
}

// transaction executes a function within a database transaction. If the
// function returns an error, the transaction is rolled back. Otherwise, the
// transaction is committed. If the transaction fails due to a busy error, it is
// retried up to 10 times before returning.
func (s *Store) transaction(fn func(*txn) error) error {
	var err error
	txnID := hex.EncodeToString(frand.Bytes(4))
	log := s.log.Named("transaction").With(zap.String("id", txnID))
	start := time.Now()
	attempt := 1
	for ; attempt < s.maxRetryAttempts; attempt++ {
		attemptStart := time.Now()
		log := log.With(zap.Int("attempt", attempt))
		err = doTransaction(s.db, log, fn)
		if err == nil {
			// no error, break out of the loop
			return nil
		}

		// return immediately if the error is not a busy error
		if !strings.Contains(err.Error(), "database is locked") {
			break
		}
		// exponential backoff
		sleep := min(time.Duration(math.Pow(backoffFactor, float64(attempt)))*time.Millisecond, maxBackoff)
		log.Debug("database locked", zap.Duration("elapsed", time.Since(attemptStart)), zap.Duration("totalElapsed", time.Since(start)), zap.Stack("stack"), zap.Duration("retry", sleep))
		jitterSleep(sleep)
	}
	return fmt.Errorf("transaction failed (attempt %d): %w", attempt, err)
}

func sqliteFilepath(fp string, busyTimeout time.Duration) string {
	params := []string{
		fmt.Sprintf("_busy_timeout=%d", busyTimeout.Milliseconds()),
		"_foreign_keys=true",
		"_journal_mode=WAL",
		"_secure_delete=false",
		"_cache_size=-65536", // 64MiB
	}
	return "file:" + fp + "?" + strings.Join(params, "&")
}

// doTransaction is a helper function to execute a function within a transaction. If fn returns
// an error, the transaction is rolled back. Otherwise, the transaction is
// committed.
func doTransaction(db *sql.DB, log *zap.Logger, fn func(tx *txn) error) error {
	dbtx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	start := time.Now()
	defer func() {
		if err := dbtx.Rollback(); err != nil && !errors.Is(err, sql.ErrTxDone) {
			log.Error("failed to rollback transaction", zap.Error(err))
		}
		// log the transaction if it took longer than txn duration
		if time.Since(start) > longTxnDuration {
			log.Debug("long transaction", zap.Duration("elapsed", time.Since(start)), zap.Stack("stack"), zap.Bool("failed", err != nil))
		}
	}()

	tx := &txn{
		Tx:  dbtx,
		log: log,
	}
	if err := fn(tx); err != nil {
		return err
	} else if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}
	return nil
}

// OpenDatabase creates a new SQLite store and initializes the database. If the
// database does not exist, it is created.
func OpenDatabase(fp string, opts ...Option) (*Store, error) {
	defaultOptions := options{
		maxRetryAttempts: 10,
		busyTimeout:      10 * time.Second,
		log:              zap.NewNop(),
	}
	for _, opt := range opts {
		opt(&defaultOptions)
	}
	db, err := sql.Open("sqlite3", sqliteFilepath(fp, defaultOptions.busyTimeout))
	if err != nil {
		return nil, err
	}
	store := &Store{
		maxRetryAttempts: defaultOptions.maxRetryAttempts,

		db:  db,
		log: defaultOptions.log,
	}
	if err := store.init(); err != nil {
		return nil, err
	}
	sqliteVersion, _, _ := sqlite3.Version()
	store.log.Debug("database initialized", zap.String("sqliteVersion", sqliteVersion), zap.Int("schemaVersion", len(migrations)+1), zap.String("path", fp))
	return store, nil
}
