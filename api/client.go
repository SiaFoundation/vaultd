package api

import (
	"context"
	"fmt"

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
func (c *Client) Sign(ctx context.Context, txn types.Transaction, opts ...SignOption) (types.Transaction, bool, error) {
	req := SignRequest{
		Transaction: txn,
	}
	for _, opt := range opts {
		opt(&req)
	}
	var resp SignResponse
	err := c.c.POST(ctx, "/sign", req, &resp)
	return resp.Transaction, resp.FullySigned, err
}

// SignV2 signs a v2 transaction using the vaultd.
func (c *Client) SignV2(ctx context.Context, txn types.V2Transaction, opts ...SignV2Option) (types.V2Transaction, bool, error) {
	req := SignV2Request{
		Transaction: txn,
	}
	for _, opt := range opts {
		opt(&req)
	}
	var resp SignV2Response
	err := c.c.POST(ctx, "/v2/sign", req, &resp)
	return resp.Transaction, resp.FullySigned, err
}

// Lock locks the vault.
func (c *Client) Lock(ctx context.Context) error {
	return c.c.PUT(ctx, "/lock", nil)
}

// Unlock unlocks the vault with the given secret.
func (c *Client) Unlock(ctx context.Context, secret string) error {
	return c.c.POST(ctx, "/unlock", &UnlockRequest{
		Secret: secret,
	}, nil)
}

// Seed returns metadata about a seed. If the seed ID is not found,
// [vault.ErrNotFound] is returned.
func (c *Client) Seed(ctx context.Context, id vault.SeedID) (SeedResponse, error) {
	var resp SeedResponse
	err := c.c.GET(ctx, fmt.Sprintf("/seeds/%d", id), &resp)
	return resp, err
}

func (c *Client) Seeds(ctx context.Context, offset, limit int) ([]vault.SeedMeta, error) {
	var resp SeedsResponse
	err := c.c.GET(ctx, fmt.Sprintf("/seeds?offset=%d&limit=%d", offset, limit), &resp)
	return resp.Seeds, err
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
