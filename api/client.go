package api

import (
	"context"
	"fmt"

	"go.sia.tech/core/consensus"
	"go.sia.tech/core/types"
	"go.sia.tech/jape"
	"go.sia.tech/vaultd/vault"
)

// A Client is an API client for the vaultd API.
type Client struct {
	c jape.Client
}

// AddSeed adds a new seed to the vault.
func (c *Client) AddSeed(ctx context.Context, recoveryPhrase string) (resp SeedResponse, err error) {
	req := AddSeedRequest{
		Phrase: recoveryPhrase,
	}
	err = c.c.POST(ctx, "/seeds", req, &resp)
	return
}

// SeedKeys returns the public keys derived from a seed.
func (c *Client) SeedKeys(ctx context.Context, id vault.SeedID) ([]SeedKey, error) {
	var resp SeedKeysResponse
	err := c.c.GET(ctx, fmt.Sprintf("/seeds/%d/keys", id), &resp)
	return resp.Keys, err
}

// GenerateKeys derives new keys from a seed.
func (c *Client) GenerateKeys(ctx context.Context, id vault.SeedID, count uint64) ([]SeedKey, error) {
	req := SeedDeriveRequest{
		Count: count,
	}
	var resp SeedKeysResponse
	err := c.c.POST(ctx, fmt.Sprintf("/seeds/%d/keys", id), req, &resp)
	return resp.Keys, err
}

// Sign signs a transaction using the vaultd.
func (c *Client) Sign(ctx context.Context, cs consensus.State, txn types.Transaction) (types.Transaction, bool, error) {
	req := SignRequest{
		State:       cs,
		Network:     *cs.Network,
		Transaction: txn,
	}
	var resp SignResponse
	err := c.c.POST(ctx, "/sign", req, &resp)
	return resp.Transaction, resp.FullySigned, err
}

// SignV2 signs a v2 transaction using the vaultd.
func (c *Client) SignV2(ctx context.Context, cs consensus.State, txn types.V2Transaction) (types.V2Transaction, bool, error) {
	req := SignV2Request{
		State:       cs,
		Network:     *cs.Network,
		Transaction: txn,
	}
	var resp SignV2Response
	err := c.c.POST(ctx, "/v2/sign", req, &resp)
	return resp.Transaction, resp.FullySigned, err
}

// NewClient creates a new API client.
func NewClient(address, password string) *Client {
	return &Client{
		c: jape.Client{
			BaseURL:  address,
			Password: password,
		},
	}
}
