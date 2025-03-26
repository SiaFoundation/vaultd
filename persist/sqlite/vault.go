package sqlite

import (
	"database/sql"
	"errors"
	"fmt"
	"time"

	"go.sia.tech/core/types"
	"go.sia.tech/vaultd/vault"
)

// KeySalt returns the salt used to derive the key encryption
// key. If no salt has been set, KeySalt returns (nil, nil).
func (s *Store) KeySalt() (salt []byte, err error) {
	err = s.transaction(func(tx *txn) error {
		err := s.db.QueryRow("SELECT key_salt FROM global_settings").Scan(&salt)
		return err
	})
	return
}

// SetKeySalt sets the salt used to derive the key encryption key.
// If a salt has already been set, [vault.ErrSaltSet] is returned.
func (s *Store) SetKeySalt(salt []byte) error {
	return s.transaction(func(tx *txn) error {
		res, err := tx.Exec("UPDATE global_settings SET key_salt = ? WHERE key_salt IS NULL", salt)
		if err != nil {
			return err
		} else if n, _ := res.RowsAffected(); n == 0 {
			return vault.ErrSaltSet
		}
		return nil
	})
}

// BytesForVerify returns random encrypted bytes for verifying
// the encryption key. If there are no keys in the store, it returns
// [vault.ErrNotFound].
func (s *Store) BytesForVerify() (buf []byte, err error) {
	err = s.transaction(func(tx *txn) error {
		err := s.db.QueryRow("SELECT encrypted_seed FROM seeds LIMIT 1").Scan(&buf)
		if errors.Is(err, sql.ErrNoRows) {
			return vault.ErrNotFound
		}
		return err
	})
	return
}

// SigningKeyIndex returns the seed and index associated with the given
// public key. If the key is not found, [vault.ErrNotFound] is returned.
func (s *Store) SigningKeyIndex(pk types.PublicKey) (id vault.SeedID, index uint64, err error) {
	err = s.transaction(func(tx *txn) error {
		err = tx.QueryRow(`SELECT seed_id, seed_index FROM signing_keys WHERE public_key=$1`, sqlPublicKey(pk)).Scan(&id, &index)
		if errors.Is(err, sql.ErrNoRows) {
			return vault.ErrNotFound
		}
		return err
	})
	return
}

// AddKeyIndex associates a public key with the given seed ID and index.
// If the key is already in the store, nil is returned.
func (s *Store) AddKeyIndex(id vault.SeedID, pk types.PublicKey, index uint64) error {
	return s.transaction(func(tx *txn) error {
		const query = `INSERT INTO signing_keys (public_key, seed_id, seed_index) VALUES ($1, $2, $3) ON CONFLICT (public_key) DO NOTHING`

		_, err := tx.Exec(query, sqlPublicKey(pk), id, index)
		return err
	})
}

func seedMeta(tx *txn, seedID vault.SeedID) (vault.SeedMeta, error) {
	meta := vault.SeedMeta{
		ID: seedID,
	}

	err := tx.QueryRow(`SELECT date_created FROM seeds WHERE id=$1`, seedID).Scan((*sqlTime)(&meta.CreatedAt))
	if errors.Is(err, sql.ErrNoRows) {
		return vault.SeedMeta{}, vault.ErrNotFound
	} else if err != nil {
		return vault.SeedMeta{}, fmt.Errorf("failed to get seed meta: %w", err)
	}

	err = tx.QueryRow(`SELECT COALESCE(MAX(seed_index), 0) FROM signing_keys WHERE seed_id=$1`, seedID).Scan(&meta.LastIndex)
	if err != nil {
		return vault.SeedMeta{}, fmt.Errorf("failed to get last index: %w", err)
	}
	return meta, nil
}

// AddSeed adds an encrypted seed to the store. If the
// seed has already been added, its metadata is returned.
func (s *Store) AddSeed(mac types.Hash256, encryptedSeed []byte) (meta vault.SeedMeta, err error) {
	err = s.transaction(func(tx *txn) error {
		err := tx.QueryRow(`INSERT INTO seeds (seed_mac, encrypted_seed, date_created) VALUES ($1, $2, $3) ON CONFLICT (seed_mac) DO UPDATE SET seed_mac=EXCLUDED.seed_mac RETURNING id`, sqlHash256(mac), encryptedSeed, sqlTime(time.Now())).Scan(&meta.ID)
		if err != nil {
			return fmt.Errorf("failed to insert seed: %w", err)
		}

		meta, err = seedMeta(tx, meta.ID)
		return err
	})
	return
}

// Seed returns the encrypted seed associated with the given
// seed ID. If the seed ID is not found, [vault.ErrNotFound] is returned.
func (s *Store) Seed(id vault.SeedID) (encryptedSeed []byte, err error) {
	err = s.transaction(func(tx *txn) error {
		err = tx.QueryRow(`SELECT encrypted_seed FROM seeds WHERE id=$1`, id).Scan(&encryptedSeed)
		if errors.Is(err, sql.ErrNoRows) {
			return vault.ErrNotFound
		}
		return err
	})
	return
}

// SeedMeta returns metadata about the seed. If the seed ID is
// not found, [vault.ErrNotFound] is returned.
func (s *Store) SeedMeta(id vault.SeedID) (meta vault.SeedMeta, err error) {
	err = s.transaction(func(tx *txn) error {
		meta, err = seedMeta(tx, id)
		return err
	})
	return
}

// SeedKeys returns a paginated list of public keys derived from the seed.
func (s *Store) SeedKeys(id vault.SeedID, offset, limit int) (keys []types.PublicKey, err error) {
	err = s.transaction(func(tx *txn) error {
		if err := checkSeedExists(tx, id); err != nil {
			return err
		}

		rows, err := tx.Query(`SELECT public_key FROM signing_keys WHERE seed_id=$1 ORDER BY seed_index ASC LIMIT $2 OFFSET $3`, id, limit, offset)
		if err != nil {
			return fmt.Errorf("failed to query keys: %w", err)
		}
		defer rows.Close()

		for rows.Next() {
			var pk sqlPublicKey
			if err := rows.Scan(&pk); err != nil {
				return fmt.Errorf("failed to scan key: %w", err)
			}
			keys = append(keys, types.PublicKey(pk))
		}
		return rows.Err()
	})
	return
}

// NextIndex returns the next index to be derived for the given seed ID.
// If the seed ID is not found, [ErrNotFound] is returned.
func (s *Store) NextIndex(seedID vault.SeedID) (index uint64, err error) {
	err = s.transaction(func(tx *txn) error {
		if err := checkSeedExists(tx, seedID); err != nil {
			return err
		}
		err = tx.QueryRow(`SELECT seed_index FROM signing_keys WHERE seed_id=$1 ORDER BY seed_index DESC LIMIT 1`, seedID).Scan(&index)
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		} else if err != nil {
			return err
		}
		index++
		return nil
	})
	return
}

func checkSeedExists(tx *txn, seedID vault.SeedID) error {
	var exists bool
	err := tx.QueryRow(`SELECT true FROM seeds WHERE id=$1`, seedID).Scan(&exists)
	if errors.Is(err, sql.ErrNoRows) {
		return vault.ErrNotFound
	} else if err != nil {
		return fmt.Errorf("failed to check seed exists: %w", err)
	}
	return nil
}
