package vault

import (
	"crypto/cipher"
	"errors"
	"fmt"
	"hash"
	"strings"
	"sync"
	"time"

	"go.sia.tech/core/types"
	"go.sia.tech/coreutils/threadgroup"
	"go.sia.tech/coreutils/wallet"
	"go.uber.org/zap"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/chacha20poly1305"
	"lukechampine.com/frand"
)

var (
	// ErrInvalidSize is returned when a key has an invalid size.
	ErrInvalidSize = errors.New("invalid key size")
	// ErrNotFound is returned when a signing key is not found.
	ErrNotFound = errors.New("not found")
	// ErrSaltSet is returned when the key salt is already set.
	ErrSaltSet = errors.New("salt already set")
	// ErrIncorrectSecret is returned when the secret is incorrect.
	ErrIncorrectSecret = errors.New("incorrect secret")
)

type (
	// A SeedID is a unique identifier for a seed.
	SeedID int64

	// SeedMeta contains metadata about a seed.
	SeedMeta struct {
		ID        SeedID
		LastIndex uint64
		CreatedAt time.Time
	}

	// A Store is a persistent store for seeds and keys.
	Store interface {
		// SigningKeyIndex returns the seed and index associated with the given
		// public key. If the key is not found, [ErrNotFound] is returned.
		SigningKeyIndex(types.PublicKey) (SeedID, uint64, error)
		// AddKeyIndex associates a public key with the given seed ID and index.
		// If the key is already in the store, nil is returned.
		AddKeyIndex(seedID SeedID, pk types.PublicKey, index uint64) error
		// NextIndex returns the next index to be derived for the given seed ID.
		// If the seed ID is not found, [ErrNotFound] is returned.
		NextIndex(seedID SeedID) (index uint64, err error)

		// KeySalt returns the salt used to derive the key encryption
		// key. If no salt has been set, KeySalt should return (nil, nil).
		KeySalt() ([]byte, error)
		// SetKeySalt sets the salt used to derive the key encryption key.
		// If a salt has already been set, [keys.ErrSaltSet] is returned.
		SetKeySalt([]byte) error

		// BytesForVerify returns random encrypted bytes for verifying
		// the encryption key.
		BytesForVerify() ([]byte, error)

		// AddSeed adds an encrypted seed to the store. If the
		// seed has already been added, its metadata is returned.
		AddSeed(mac types.Hash256, encryptedSeed []byte) (meta SeedMeta, err error)
		// Seed returns the encrypted seed associated with the given
		// seed ID. If the seed ID is not found, [ErrNotFound] is returned.
		Seed(SeedID) ([]byte, error)
		// SeedMeta returns metadata about the seed. If the seed ID is
		// not found, [ErrNotFound] is returned.
		SeedMeta(SeedID) (SeedMeta, error)
		// SeedKeys returns a paginated list of public keys derived from the seed.
		SeedKeys(id SeedID, offset, limit int) ([]types.PublicKey, error)
	}

	// A Vault is a secure store for recovery phrases
	Vault struct {
		tg *threadgroup.ThreadGroup

		aead  cipher.AEAD
		mac   hash.Hash
		store Store

		mu sync.Mutex // protects atomicity of key derivation
	}
)

// Close closes the Vault.
func (v *Vault) Close() error {
	v.tg.Stop()
	return nil
}

func (v *Vault) derivePrivateKey(id SeedID, index uint64) (types.PrivateKey, error) {
	encryptedSeed, err := v.store.Seed(id)
	if err != nil {
		return types.PrivateKey{}, fmt.Errorf("failed to get seed: %w", err)
	}
	defer clear(encryptedSeed)

	var seed [32]byte
	defer clear(seed[:])
	buf, err := v.aead.Open(seed[:0], encryptedSeed[:v.aead.NonceSize()], encryptedSeed[v.aead.NonceSize():], nil)
	if err != nil {
		return types.PrivateKey{}, fmt.Errorf("failed to decrypt seed: %w", err)
	} else if len(buf) != 32 {
		panic(fmt.Errorf("unexpected seed size %d: %w", len(buf), ErrInvalidSize)) // developer error
	}
	return wallet.KeyFromSeed(&seed, index), nil
}

// Sign returns the signature for a hash. If the key is not
// found, it returns [ErrNotFound].
func (v *Vault) Sign(pk types.PublicKey, hash types.Hash256) (types.Signature, error) {
	done, err := v.tg.Add()
	if err != nil {
		return types.Signature{}, err
	}
	defer done()

	seedID, index, err := v.store.SigningKeyIndex(pk)
	if err != nil {
		return types.Signature{}, fmt.Errorf("failed to get signing key: %w", err)
	}

	sk, err := v.derivePrivateKey(seedID, index)
	if err != nil {
		return types.Signature{}, fmt.Errorf("failed to derive private key: %w", err)
	}
	defer clear(sk)
	return sk.SignHash(hash), nil
}

// AddSeed adds a seed to the Vault and returns its ID. If the seed has
// already been added, the existing ID is returned.
func (v *Vault) AddSeed(seed *[32]byte) (SeedMeta, error) {
	done, err := v.tg.Add()
	if err != nil {
		return SeedMeta{}, err
	}
	defer done()

	v.mu.Lock()
	defer v.mu.Unlock()

	v.mac.Reset()
	if _, err := v.mac.Write(seed[:]); err != nil {
		return SeedMeta{}, fmt.Errorf("failed to write seed to mac: %w", err)
	}
	mac := types.Hash256(v.mac.Sum(nil))

	n := v.aead.NonceSize()
	buf := make([]byte, n, n+len(seed)+v.aead.Overhead())
	frand.Read(buf[:n])
	encrypted := v.aead.Seal(buf, buf, seed[:], nil)
	defer clear(encrypted)
	return v.store.AddSeed(mac, encrypted)
}

// SeedMeta returns metadata about the seed. If the seed ID is not found,
// [ErrNotFound] is returned.
func (v *Vault) SeedMeta(id SeedID) (SeedMeta, error) {
	done, err := v.tg.Add()
	if err != nil {
		return SeedMeta{}, err
	}
	defer done()

	v.mu.Lock()
	defer v.mu.Unlock()
	return v.store.SeedMeta(id)
}

// SeedKeys returns a paginated list of public keys derived from the seed.
func (v *Vault) SeedKeys(id SeedID, offset, limit int) ([]types.PublicKey, error) {
	done, err := v.tg.Add()
	if err != nil {
		return nil, err
	}
	defer done()

	v.mu.Lock()
	defer v.mu.Unlock()
	return v.store.SeedKeys(id, offset, limit)
}

// NextKey returns the next public key derived from the seed.
func (v *Vault) NextKey(id SeedID) (types.PublicKey, error) {
	done, err := v.tg.Add()
	if err != nil {
		return types.PublicKey{}, err
	}
	defer done()

	v.mu.Lock()
	defer v.mu.Unlock()

	index, err := v.store.NextIndex(id)
	if err != nil {
		return types.PublicKey{}, fmt.Errorf("failed to get next index: %w", err)
	}

	sk, err := v.derivePrivateKey(id, index)
	if err != nil {
		return types.PublicKey{}, fmt.Errorf("failed to derive private key: %w", err)
	}
	defer clear(sk)

	if err := v.store.AddKeyIndex(id, sk.PublicKey(), index); err != nil {
		return types.PublicKey{}, fmt.Errorf("failed to add key index: %w", err)
	}
	return sk.PublicKey(), nil
}

// New creates a new Vault with the given secret. If the secret is
// incorrect, it returns [ErrIncorrectSecret].
func New(s Store, secret string, log *zap.Logger) (*Vault, error) {
	salt, err := s.KeySalt()
	if err != nil {
		return nil, fmt.Errorf("failed to get key salt: %w", err)
	} else if len(salt) == 0 {
		salt = frand.Bytes(32)
		if err := s.SetKeySalt(salt); err != nil {
			return nil, fmt.Errorf("failed to set key salt: %w", err)
		}
	}

	encryptionKey := argon2.IDKey([]byte(secret), salt, 3, 64*1024, 4, 32)
	aead, err := chacha20poly1305.NewX(encryptionKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create AEAD: %w", err)
	}

	mac, err := blake2b.New256(encryptionKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create MAC: %w", err)
	}

	buf, err := s.BytesForVerify()
	if err != nil && !errors.Is(err, ErrNotFound) {
		return nil, fmt.Errorf("failed to get bytes for verify: %w", err)
	} else if err == nil {
		defer clear(buf)

		_, err := aead.Open(buf[aead.NonceSize():], buf[:aead.NonceSize()], buf[aead.NonceSize():], nil)
		if err != nil {
			if strings.Contains(err.Error(), "message authentication failed") {
				return nil, ErrIncorrectSecret
			}
			return nil, fmt.Errorf("failed to verify encryption key: %w", err)
		}
	}
	return &Vault{
		tg:    threadgroup.New(),
		store: s,
		aead:  aead,
		mac:   mac,
	}, nil
}
