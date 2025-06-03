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

type chain struct {
	cs consensus.State
}

func (c *chain) TipState(ctx context.Context) (consensus.State, error) {
	return c.cs, nil
}

func startServer(tb testing.TB, chain Chain, secret string) (client *Client) {
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
		Handler: Handler(chain, vault, log.Named("api")),
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
	client := startServer(t, &chain{}, "foo bar baz")

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
	client := startServer(t, &chain{}, "foo bar baz")

	phrase := "mocked southern dehydrate unusual navy pegs aided ruined festival yearbook total building wife greater befit drunk judge thwart erosion hefty saucepan hijack request welders bomb remedy each sayings actress"

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
	client := startServer(t, &chain{}, "foo bar baz")

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

	txn, signed, err := client.Sign(context.Background(), txn, SignWithState(cs))
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
	client := startServer(t, &chain{}, "foo bar baz")

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

	txn, signed, err := client.SignV2(context.Background(), txn, SignV2WithState(cs))
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

func TestSignLoadState(t *testing.T) {
	cs := consensus.State{
		Network: &consensus.Network{
			HardforkFoundation: struct {
				Height          uint64        `json:"height"`
				PrimaryAddress  types.Address `json:"primaryAddress"`
				FailsafeAddress types.Address `json:"failsafeAddress"`
			}{
				Height: 8,
			},
			HardforkV2: struct {
				AllowHeight   uint64 `json:"allowHeight"`
				RequireHeight uint64 `json:"requireHeight"`
			}{
				AllowHeight:   10,
				RequireHeight: 20,
			},
		},
		Index: types.ChainIndex{
			Height: 8, // before v2 hardfork to ensure the replay prefix is 1
			ID:     frand.Entropy256(),
		},
	}
	ch := &chain{cs}
	client := startServer(t, ch, "foo bar baz")

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

	sigHash := cs.WholeSigHash(txn, txn.Signatures[0].ParentID, 0, 0, nil)

	signedTxn, signed, err := client.Sign(context.Background(), txn)
	if err != nil {
		t.Fatal(err)
	} else if !signed {
		t.Fatal("expected transaction to be signed")
	}
	signature := types.Signature(signedTxn.Signatures[0].Signature)
	if !wallet.KeyFromSeed(&seed, 0).PublicKey().VerifyHash(sigHash, signature) {
		t.Fatal("signature verification failed")
	}

	ch.cs.Index.Height = 10 // after v2 hardfork to ensure the replay prefix updates
	cs = ch.cs

	signedTxn2, signed, err := client.Sign(context.Background(), txn)
	if err != nil {
		t.Fatal(err)
	} else if !signed {
		t.Fatal("expected transaction to be signed")
	}
	signature2 := types.Signature(signedTxn2.Signatures[0].Signature)
	if signature2 == signature {
		t.Fatal("expected different signature after changing replay prefix")
	}

	sigHash = cs.WholeSigHash(txn, txn.Signatures[0].ParentID, 0, 0, nil)
	if !wallet.KeyFromSeed(&seed, 0).PublicKey().VerifyHash(sigHash, signature2) {
		t.Fatal("signature verification failed")
	}
}

func TestSignV2LoadState(t *testing.T) {
	cs := consensus.State{
		Network: &consensus.Network{
			HardforkFoundation: struct {
				Height          uint64        `json:"height"`
				PrimaryAddress  types.Address `json:"primaryAddress"`
				FailsafeAddress types.Address `json:"failsafeAddress"`
			}{
				Height: 8,
			},
			HardforkV2: struct {
				AllowHeight   uint64 `json:"allowHeight"`
				RequireHeight uint64 `json:"requireHeight"`
			}{
				AllowHeight:   10,
				RequireHeight: 20,
			},
		},
		Index: types.ChainIndex{
			Height: 10,
			ID:     frand.Entropy256(),
		},
	}
	ch := &chain{cs}
	client := startServer(t, ch, "foo bar baz")

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

	sigHash := cs.InputSigHash(txn)

	txn, signed, err := client.SignV2(context.Background(), txn)
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
	client := startServer(t, &chain{}, "")

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
