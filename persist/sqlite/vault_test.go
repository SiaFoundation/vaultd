package sqlite

import (
	"path/filepath"
	"testing"

	"lukechampine.com/frand"
)

func TestVaultSeeds(t *testing.T) {
	db, err := OpenDatabase(filepath.Join(t.TempDir(), "vaultd.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	seeds, err := db.Seeds(100, 0)
	if err != nil {
		t.Fatal(err)
	} else if len(seeds) != 0 {
		t.Fatal("expected 0 seeds, got", len(seeds))
	}

	meta, err := db.AddSeed(frand.Entropy256(), frand.Bytes(72))
	if err != nil {
		t.Fatal(err)
	} else if meta.ID != 1 {
		t.Fatalf("expected ID 1, got %d", meta.ID)
	} else if meta.LastIndex != 0 {
		t.Fatalf("expected LastIndex 0, got %d", meta.LastIndex)
	} else if meta.CreatedAt.IsZero() {
		t.Fatal("expected CreatedAt to be set")
	}

	seeds, err = db.Seeds(100, 0)
	if err != nil {
		t.Fatal(err)
	} else if len(seeds) != 1 {
		t.Fatal("expected 1 seed, got", len(seeds))
	} else if seeds[0].ID != meta.ID {
		t.Fatalf("expected ID %d, got %d", meta.ID, seeds[0].ID)
	} else if seeds[0].CreatedAt != meta.CreatedAt {
		t.Fatalf("expected CreatedAt %v, got %v", meta.CreatedAt, seeds[0].CreatedAt)
	} else if seeds[0].LastIndex != meta.LastIndex {
		t.Fatalf("expected LastIndex %d, got %d", meta.LastIndex, seeds[0].LastIndex)
	}

	for i := uint64(0); i < 100; i++ {
		if err := db.AddKeyIndex(meta.ID, frand.Entropy256(), i); err != nil {
			t.Fatal(err)
		}
	}

	seeds, err = db.Seeds(100, 0)
	if err != nil {
		t.Fatal(err)
	} else if len(seeds) != 1 {
		t.Fatal("expected 1 seeds, got", len(seeds))
	} else if seeds[0].ID != meta.ID {
		t.Fatalf("expected ID %d, got %d", meta.ID, seeds[0].ID)
	} else if seeds[0].CreatedAt != meta.CreatedAt {
		t.Fatalf("expected CreatedAt %v, got %v", meta.CreatedAt, seeds[0].CreatedAt)
	} else if seeds[0].LastIndex != 99 {
		t.Fatalf("expected LastIndex %d, got %d", 99, seeds[0].LastIndex)
	}
}
