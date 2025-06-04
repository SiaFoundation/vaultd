package siad

import (
	"bytes"
	"encoding/hex"
	"testing"

	"go.sia.tech/core/types"
	"go.sia.tech/coreutils/wallet"
)

func TestMnemonic(t *testing.T) {
	phrase := "oval rockets slug umpire dizzy rekindle jester plus opened dauntless dummy origin cake oasis gimmick jogger dejected amnesty goes mystery cistern gawk algebra revamp rotate fitting coils vastness absorb"

	expectedSeed, err := hex.DecodeString("f0c2fb993fec7b892b8a5fbfba95fb4400558a3c3cc4b536258217e13db0b872")
	if err != nil {
		t.Fatal(err)
	}

	expectedAddresses := map[uint64]string{
		0:                    "d7b1cca352f3223ab5ec87204ee223895e49b539dea5506039aeda163c525fc486b2f2df01b8",
		4294967295:           "f1f8693eba9c38ca9f58a919c10490cf049e9c55585bf91812bb9eafac296cf6551f4625f68b",
		18446744073709551615: "6bb3915d60194a469340f91e07a89da26805b853620a23aacc6b3678c3a700939fef54ae17c3",
	}

	var seed [32]byte
	if err = SeedFromPhrase(&seed, phrase); err != nil {
		t.Fatal(err)
	} else if !bytes.Equal(seed[:], expectedSeed) {
		t.Fatalf("unexpected seed: expected %x, got %x", expectedSeed, seed)
	}

	for i, expected := range expectedAddresses {
		addr := types.StandardUnlockHash(wallet.KeyFromSeed(&seed, i).PublicKey())
		if addr.String() != expected {
			t.Fatalf("unexpected address: expected %q, got %q", expected, addr.String())
		}
	}
}
