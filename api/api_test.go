package api

import (
	"context"
	"net"
	"net/http"
	"path/filepath"
	"testing"

	"go.sia.tech/core/consensus"
	"go.sia.tech/core/types"
	"go.sia.tech/coreutils/wallet"
	"go.sia.tech/vaultd/internal/siad"
	"go.sia.tech/vaultd/persist/sqlite"
	"go.sia.tech/vaultd/vault"
	"go.uber.org/zap"
	"lukechampine.com/frand"
)

func startServer(tb testing.TB, secret string) (client *Client) {
	tb.Helper()
	log := zap.NewNop()

	l, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		tb.Fatal(err)
	}
	tb.Cleanup(func() { l.Close() })

	store, err := sqlite.OpenDatabase(filepath.Join(tb.TempDir(), "vaultd.sqlite3"), sqlite.WithLogger(log.Named("sqlite3")))
	if err != nil {
		tb.Fatal(err)
	}
	tb.Cleanup(func() { store.Close() })

	vault := vault.New(store)
	tb.Cleanup(func() { vault.Close() })
	if secret != "" {
		if err := vault.Unlock(secret); err != nil {
			tb.Fatal(err)
		}
	}

	s := &http.Server{
		Handler: Handler(vault, log.Named("api")),
	}
	tb.Cleanup(func() { s.Close() })
	go func() {
		if err := s.Serve(l); err != http.ErrServerClosed {
			tb.Fatal(err)
		}
	}()

	return NewClient("http://"+l.Addr().String(), "")
}

func TestAddSeed(t *testing.T) {
	client := startServer(t, "foo bar baz")

	phrase := wallet.NewSeedPhrase()

	var seed [32]byte
	if err := wallet.SeedFromPhrase(&seed, phrase); err != nil {
		t.Fatal(err)
	}

	meta, err := client.AddSeed(context.Background(), phrase)
	if err != nil {
		t.Fatal(err)
	} else if meta.ID != 1 {
		t.Fatalf("expected ID 1, got %d", meta.ID)
	}

	keys, err := client.GenerateKeys(context.Background(), meta.ID, 100)
	if err != nil {
		t.Fatal(err)
	}

	for i, key := range keys {
		expectedKey := wallet.KeyFromSeed(&seed, uint64(i)).PublicKey()
		expectedAddr := types.StandardUnlockHash(expectedKey)

		switch {
		case key.PublicKey != expectedKey:
			t.Errorf("key %d: expected public key %x, got %x", i, expectedKey, key.PublicKey)
		case key.Address != expectedAddr:
			t.Errorf("key %d: expected address %s, got %s", i, expectedAddr, key.Address)
		case key.SpendPolicy.Address() != expectedAddr:
			t.Errorf("key %d: expected spend policy %v", i, key.SpendPolicy)
		}
	}
}

func TestAddSiadSeed(t *testing.T) {
	client := startServer(t, "foo bar baz")

	phrase := "touchy inroads aptitude perfect seventh tycoon zinger madness firm cause diode owls meant knife nuisance skirting umpire sapling reruns batch molten urchins jaded nodes"

	var seed [32]byte
	if err := siad.SeedFromPhrase(&seed, phrase); err != nil {
		t.Fatal(err)
	}

	meta, err := client.AddSeed(context.Background(), phrase)
	if err != nil {
		t.Fatal(err)
	} else if meta.ID != 1 {
		t.Fatalf("expected ID 1, got %d", meta.ID)
	}

	keys, err := client.GenerateKeys(context.Background(), meta.ID, 100)
	if err != nil {
		t.Fatal(err)
	}

	for i, key := range keys {
		expectedKey := wallet.KeyFromSeed(&seed, uint64(i)).PublicKey()
		expectedAddr := types.StandardUnlockHash(expectedKey)

		switch {
		case key.PublicKey != expectedKey:
			t.Errorf("key %d: expected public key %x, got %x", i, expectedKey, key.PublicKey)
		case key.Address != expectedAddr:
			t.Errorf("key %d: expected address %s, got %s", i, expectedAddr, key.Address)
		case key.SpendPolicy.Address() != expectedAddr:
			t.Errorf("key %d: expected spend policy %v", i, key.SpendPolicy)
		}
	}
}

func TestSignV1(t *testing.T) {
	client := startServer(t, "foo bar baz")

	phrase := wallet.NewSeedPhrase()

	var seed [32]byte
	if err := wallet.SeedFromPhrase(&seed, phrase); err != nil {
		t.Fatal(err)
	}

	meta, err := client.AddSeed(context.Background(), phrase)
	if err != nil {
		t.Fatal(err)
	} else if meta.ID != 1 {
		t.Fatalf("expected ID 1, got %d", meta.ID)
	}

	_, err = client.GenerateKeys(context.Background(), meta.ID, 5)
	if err != nil {
		t.Fatal(err)
	}

	txn := types.Transaction{
		SiacoinInputs: []types.SiacoinInput{
			{
				ParentID: frand.Entropy256(),
				UnlockConditions: types.UnlockConditions{
					PublicKeys: []types.UnlockKey{
						wallet.KeyFromSeed(&seed, 0).PublicKey().UnlockKey(),
					},
					SignaturesRequired: 1,
				},
			},
		},
	}
	txn.Signatures = []types.TransactionSignature{
		{
			ParentID:      types.Hash256(txn.SiacoinInputs[0].ParentID),
			CoveredFields: types.CoveredFields{WholeTransaction: true},
		},
	}

	cs := consensus.State{
		Network: &consensus.Network{
			HardforkV2: struct {
				AllowHeight   uint64 `json:"allowHeight"`
				RequireHeight uint64 `json:"requireHeight"`
			}{
				AllowHeight:   10,
				RequireHeight: 20,
			},
		},
		Index: types.ChainIndex{
			Height: 5,
			ID:     frand.Entropy256(),
		},
	}

	sigHash := cs.WholeSigHash(txn, txn.Signatures[0].ParentID, 0, 0, nil)

	txn, signed, err := client.Sign(context.Background(), cs, txn)
	if err != nil {
		t.Fatal(err)
	} else if !signed {
		t.Fatal("expected transaction to be signed")
	}
	signature := types.Signature(txn.Signatures[0].Signature)
	if !wallet.KeyFromSeed(&seed, 0).PublicKey().VerifyHash(sigHash, signature) {
		t.Fatal("signature verification failed")
	}
}

func TestSignV2(t *testing.T) {
	client := startServer(t, "foo bar baz")

	phrase := wallet.NewSeedPhrase()

	var seed [32]byte
	if err := wallet.SeedFromPhrase(&seed, phrase); err != nil {
		t.Fatal(err)
	}

	pk := wallet.KeyFromSeed(&seed, 0).PublicKey()

	meta, err := client.AddSeed(context.Background(), phrase)
	if err != nil {
		t.Fatal(err)
	} else if meta.ID != 1 {
		t.Fatalf("expected ID 1, got %d", meta.ID)
	}

	_, err = client.GenerateKeys(context.Background(), meta.ID, 5)
	if err != nil {
		t.Fatal(err)
	}

	txn := types.V2Transaction{
		SiacoinInputs: []types.V2SiacoinInput{
			{
				Parent: types.SiacoinElement{
					ID: frand.Entropy256(),
				},
				SatisfiedPolicy: types.SatisfiedPolicy{
					Policy: types.SpendPolicy{
						Type: types.PolicyTypePublicKey(pk),
					},
				},
			},
		},
	}

	cs := consensus.State{
		Network: &consensus.Network{},
		Index: types.ChainIndex{
			Height: 5,
			ID:     frand.Entropy256(),
		},
	}

	sigHash := cs.InputSigHash(txn)

	txn, signed, err := client.SignV2(context.Background(), cs, txn)
	if err != nil {
		t.Fatal(err)
	} else if !signed {
		t.Fatal("expected transaction to be signed")
	}
	signature := txn.SiacoinInputs[0].SatisfiedPolicy.Signatures[0]
	if !wallet.KeyFromSeed(&seed, 0).PublicKey().VerifyHash(sigHash, signature) {
		t.Fatal("signature verification failed")
	}
}

func TestLockUnlock(t *testing.T) {
	client := startServer(t, "")

	phrase := wallet.NewSeedPhrase()

	_, err := client.AddSeed(context.Background(), phrase)
	if err.Error() != "vault is locked" {
		t.Fatalf("expected \"vault is locked\", got %q", err)
	}

	// first call to unlock initializes the vault
	if err := client.Unlock(context.Background(), "foo bar baz"); err != nil {
		t.Fatal(err)
	} else if err := client.Lock(context.Background()); err != nil {
		t.Fatal(err)
	}

	_, err = client.AddSeed(context.Background(), phrase)
	if err.Error() != "vault is locked" {
		t.Fatalf("expected \"vault is locked\", got %q", err)
	}

	if err := client.Unlock(context.Background(), "foo bar baz"); err != nil {
		t.Fatal(err)
	}

	meta, err := client.AddSeed(context.Background(), phrase)
	if err != nil {
		t.Fatal(err)
	} else if meta.ID != 1 {
		t.Fatalf("expected ID 1, got %d", meta.ID)
	}

	if _, err := client.GenerateKeys(context.Background(), meta.ID, 5); err != nil {
		t.Fatal(err)
	}

	// relock and try to unlock with the wrong password
	if err := client.Lock(context.Background()); err != nil {
		t.Fatal(err)
	} else if err := client.Unlock(context.Background(), "wrong password"); err.Error() != vault.ErrIncorrectSecret.Error() {
		t.Fatalf("expected \"incorrect secret\", got %q", err)
	}
}
