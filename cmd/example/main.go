package main

import (
	"context"
	"log"

	"go.sia.tech/vaultd/api"
)

func main() {
	const (
		apiAddress    = "http://localhost:8080"
		apiPassword   = "my api password"
		vaultPassword = "foo bar baz"

		seedPhrase = "mocked limits energy lyrics tacit evenings deity icon tether wrap idols rift tacit huge light hire powder licks liquid pedantic afar goodbye iguana acoustic initiate womanly obliged argue abort"
	)
	client := api.NewClient(apiAddress, apiPassword)

	// first call to unlock initializes the vault
	if err := client.Unlock(context.Background(), vaultPassword); err != nil {
		panic(err)
	}
	defer client.Lock(context.Background())

	// add a seed to the vault
	// [POST] /seed { "recoveryPhrase": "..." }
	resp, err := client.AddSeed(context.Background(), seedPhrase)
	if err != nil {
		panic(err)
	}

	// generate an address from the seed
	// [POST] /seed/{id}/address { "count": 1 }
	genResp, err := client.GenerateKeys(context.Background(), resp.ID, 1)
	if err != nil {
		panic(err)
	}

	log.Println(genResp[0].Address)
}
