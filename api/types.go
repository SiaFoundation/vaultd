package api

import (
	"time"

	"go.sia.tech/core/consensus"
	"go.sia.tech/core/types"
	"go.sia.tech/vaultd/vault"
)

type (
	// A StateResponse returns information about the current state of the walletd
	// daemon.
	StateResponse struct {
		Version   string    `json:"version"`
		Commit    string    `json:"commit"`
		OS        string    `json:"os"`
		BuildTime time.Time `json:"buildTime"`
		StartTime time.Time `json:"startTime"`
	}

	// An AddSeedRequest is a request to add a seed to the vault.
	AddSeedRequest struct {
		Phrase string `json:"phrase"`
	}

	// SeedsResponse is a response to a seeds request.
	SeedsResponse struct {
		Seeds []vault.SeedMeta `json:"seeds"`
	}

	// SeedResponse is a response to a seed request.
	SeedResponse struct {
		ID        vault.SeedID `json:"id"`
		LastIndex uint64       `json:"lastIndex"`
		CreatedAt time.Time    `json:"createdAt"`
	}

	// SeedKey is a public key and its associated standard address.
	SeedKey struct {
		PublicKey   types.PublicKey   `json:"publicKey"`
		Address     types.Address     `json:"address"`
		SpendPolicy types.SpendPolicy `json:"spendPolicy"`
	}

	// SeedKeysResponse is a response to a seed keys request.
	SeedKeysResponse struct {
		Keys []SeedKey `json:"keys"`
	}

	// SeedDeriveRequest is a request to derive a set of keys from a seed.
	SeedDeriveRequest struct {
		Count uint64 `json:"count"`
	}

	// SignRequest is a request to sign a transaction.
	SignRequest struct {
		State       consensus.State   `json:"state"`
		Network     consensus.Network `json:"network"`
		Transaction types.Transaction `json:"transaction"`
	}

	// SignResponse is a response to a sign request.
	SignResponse struct {
		Transaction types.Transaction `json:"transaction"`
		FullySigned bool              `json:"fullySigned"`
	}

	// SignV2Request is a request to sign a v2 transaction.
	SignV2Request struct {
		State       consensus.State     `json:"state"`
		Network     consensus.Network   `json:"network"`
		Transaction types.V2Transaction `json:"transaction"`
	}

	// SignV2Response is a response to a sign v2 request.
	SignV2Response struct {
		Transaction types.V2Transaction `json:"transaction"`
		FullySigned bool                `json:"fullySigned"`
	}

	// An UnlockRequest is a request to unlock the vault.
	// The secret is the key used to unlock the vault.
	UnlockRequest struct {
		Secret string `json:"secret"`
	}
)
