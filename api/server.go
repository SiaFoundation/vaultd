package api

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"net/http"
	"runtime"
	"strings"
	"time"

	"go.sia.tech/core/types"
	"go.sia.tech/coreutils/wallet"
	"go.sia.tech/jape"
	"go.sia.tech/vaultd/build"
	"go.sia.tech/vaultd/internal/siad"
	"go.sia.tech/vaultd/vault"
	"go.uber.org/zap"
)

var startTime = time.Now()

type (
	api struct {
		vault *vault.Vault
		log   *zap.Logger
	}
)

func (a *api) handleGETState(jc jape.Context) {
	jc.Encode(StateResponse{
		Version:   build.Version(),
		Commit:    build.Commit(),
		OS:        runtime.GOOS,
		BuildTime: build.Time(),
		StartTime: startTime,
	})
}

func (a *api) handlePOSTSeeds(jc jape.Context) {
	var req AddSeedRequest
	if err := jc.Decode(&req); err != nil {
		return
	}

	var seed [32]byte
	defer clear(seed[:])
	if len(strings.Fields(req.Phrase)) != 12 {
		if err := siad.SeedFromPhrase(&seed, req.Phrase); err != nil {
			jc.Error(err, http.StatusBadRequest)
			return
		}
	} else {
		if err := wallet.SeedFromPhrase(&seed, req.Phrase); err != nil {
			jc.Error(err, http.StatusBadRequest)
			return
		}
	}

	meta, err := a.vault.AddSeed(&seed)
	if err != nil {
		jc.Error(err, http.StatusInternalServerError)
		return
	}
	jc.Encode(meta)
}

func (a *api) handleGETSeedsID(jc jape.Context) {
	var id vault.SeedID
	if err := jc.DecodeParam("id", (*int64)(&id)); err != nil {
		return
	}

	meta, err := a.vault.SeedMeta(id)
	if errors.Is(err, vault.ErrNotFound) {
		jc.Error(err, http.StatusNotFound)
	} else if err != nil {
		jc.Error(err, http.StatusInternalServerError)
		return
	}
	jc.Encode(SeedResponse{
		ID:        meta.ID,
		LastIndex: meta.LastIndex,
		CreatedAt: meta.CreatedAt,
	})
}

func (a *api) handleGETSeedsKeys(jc jape.Context) {
	limit := 100
	offset := 0
	if err := jc.DecodeForm("limit", &limit); err != nil {
		return
	} else if err := jc.DecodeForm("offset", &offset); err != nil {
		return
	} else if limit < 1 || limit > 500 {
		jc.Error(errors.New("limit must be between 1 and 500"), http.StatusBadRequest)
		return
	} else if offset < 0 {
		jc.Error(errors.New("offset must be non-negative"), http.StatusBadRequest)
		return
	}

	var id vault.SeedID
	if err := jc.DecodeParam("id", (*int64)(&id)); err != nil {
		return
	}

	keys, err := a.vault.SeedKeys(id, offset, limit)
	if errors.Is(err, vault.ErrNotFound) {
		jc.Error(err, http.StatusNotFound)
	} else if err != nil {
		jc.Error(err, http.StatusInternalServerError)
		return
	}

	resp := SeedKeysResponse{
		Keys: make([]SeedKey, len(keys)),
	}

	for i, key := range keys {
		resp.Keys[i].PublicKey = key
		resp.Keys[i].SpendPolicy = types.SpendPolicy{
			Type: types.PolicyTypeUnlockConditions(types.StandardUnlockConditions(key)),
		}
		resp.Keys[i].Address = resp.Keys[i].SpendPolicy.Address()
	}
	jc.Encode(resp)
}

func (a *api) handlePOSTSeedsKeys(jc jape.Context) {
	var req SeedDeriveRequest
	if err := jc.Decode(&req); err != nil {
		return
	}
	var id vault.SeedID
	if err := jc.DecodeParam("id", (*int64)(&id)); err != nil {
		return
	}

	resp := SeedKeysResponse{
		Keys: make([]SeedKey, req.Count),
	}
	for i := uint64(0); i < req.Count; i++ {
		key, err := a.vault.NextKey(id)
		if err != nil {
			jc.Error(err, http.StatusInternalServerError)
			return
		}
		resp.Keys[i].PublicKey = key
		resp.Keys[i].SpendPolicy = types.SpendPolicy{
			Type: types.PolicyTypeUnlockConditions(types.StandardUnlockConditions(key)),
		}
		resp.Keys[i].Address = resp.Keys[i].SpendPolicy.Address()
	}
	jc.Encode(resp)
}

func (a *api) handlePOSTSign(jc jape.Context) {
	var req SignRequest
	if err := jc.Decode(&req); err != nil {
		return
	}

	cs := req.State
	cs.Network = &req.Network

	if cs.Index.Height >= cs.Network.HardforkV2.RequireHeight {
		jc.Error(errors.New("v1 transactions are not supported after the require height"), http.StatusBadRequest)
		return
	}

	txn := req.Transaction

	publicKeyForSigning := func(id types.Hash256, pubKeyIndex uint64) (types.PublicKey, bool) {
		getUnlockConditions := func(id types.Hash256) (types.UnlockConditions, bool) {
			for _, input := range txn.SiacoinInputs {
				if types.Hash256(input.ParentID) == id {
					return input.UnlockConditions, true
				}
			}
			for _, input := range txn.SiafundInputs {
				if types.Hash256(input.ParentID) == id {
					return input.UnlockConditions, true
				}
			}
			return types.UnlockConditions{}, false
		}

		uc, ok := getUnlockConditions(id)
		if !ok {
			return types.PublicKey{}, false
		} else if pubKeyIndex >= uint64(len(uc.PublicKeys)) {
			return types.PublicKey{}, false
		}

		uk := uc.PublicKeys[pubKeyIndex]
		if uk.Algorithm != types.SpecifierEd25519 {
			return types.PublicKey{}, false
		} else if len(uk.Key) != ed25519.PublicKeySize {
			return types.PublicKey{}, false
		}
		return types.PublicKey(uk.Key), true
	}

	var signed int
	for i, sig := range txn.Signatures {
		if sig.Signature != nil {
			signed++
			continue
		}

		pk, ok := publicKeyForSigning(sig.ParentID, sig.PublicKeyIndex)
		if !ok {
			continue
		}

		var sigHash types.Hash256
		if sig.CoveredFields.WholeTransaction {
			sigHash = cs.WholeSigHash(txn, sig.ParentID, sig.PublicKeyIndex, sig.Timelock, nil)
		} else {
			sigHash = cs.PartialSigHash(txn, sig.CoveredFields)
		}

		signature, err := a.vault.Sign(pk, sigHash)
		if errors.Is(err, vault.ErrNotFound) {
			continue
		} else if err != nil {
			jc.Error(err, http.StatusInternalServerError)
			return
		}
		txn.Signatures[i].Signature = signature[:]
		signed++
	}

	if signed == 0 {
		jc.Error(errors.New("no signatures were added"), http.StatusBadRequest)
		return
	}
	jc.Encode(SignResponse{Transaction: txn, FullySigned: signed == len(txn.Signatures)})
}

func (a *api) handlePOSTSignV2(jc jape.Context) {
	var req SignV2Request
	if err := jc.Decode(&req); err != nil {
		return
	}

	txn := req.Transaction

	cs := req.State
	cs.Network = &req.Network

	if cs.Index.Height < cs.Network.HardforkV2.AllowHeight {
		jc.Error(errors.New("v2 transactions are not supported until after the allow height"), http.StatusBadRequest)
		return
	}

	sigHash := cs.InputSigHash(txn)

	var signPolicy func(policy types.SpendPolicy, signatures *[]types.Signature) error
	signPolicy = func(policy types.SpendPolicy, signatures *[]types.Signature) error {
		switch policy := policy.Type.(type) {
		case types.PolicyTypeThreshold:
			var signed uint8
			for _, sub := range policy.Of {
				if signed == policy.N {
					break
				}

				if err := signPolicy(sub, signatures); err != nil {
					return err
				}
				signed++
			}
			if signed < policy.N {
				return fmt.Errorf("policy %q threshold not met %d != %d", policy, signed, policy.N)
			}
		case types.PolicyTypePublicKey:
			sig, err := a.vault.Sign(types.PublicKey(policy), sigHash)
			if errors.Is(err, vault.ErrNotFound) {
				return nil
			} else if err != nil {
				return fmt.Errorf("failed to sign policy %q: %w", policy, err)
			}
			*signatures = append(*signatures, sig)
		case types.PolicyTypeUnlockConditions:
			var signed uint64
			for i := range policy.PublicKeys {
				if signed == policy.SignaturesRequired {
					break
				} else if policy.PublicKeys[i].Algorithm != types.SpecifierEd25519 || len(policy.PublicKeys[i].Key) != ed25519.PublicKeySize {
					return fmt.Errorf("unsupported public key algorithm %v", policy.PublicKeys[i].Algorithm)
				}
				pk := types.PublicKey(policy.PublicKeys[i].Key)

				sig, err := a.vault.Sign(pk, sigHash)
				if errors.Is(err, vault.ErrNotFound) {
					continue
				} else if err != nil {
					return fmt.Errorf("failed to sign policy %q: %w", policy, err)
				}
				*signatures = append(*signatures, sig)
				signed++
			}
			if signed < policy.SignaturesRequired {
				return fmt.Errorf("policy %q required signatures not met %d != %d", policy, signed, policy.SignaturesRequired)
			}
		}
		return nil
	}

	signed := true
	for i := range txn.SiacoinInputs {
		if err := signPolicy(txn.SiacoinInputs[i].SatisfiedPolicy.Policy, &txn.SiacoinInputs[i].SatisfiedPolicy.Signatures); err != nil {
			signed = false
		}
	}
	for i := range txn.SiafundInputs {
		if err := signPolicy(txn.SiafundInputs[i].SatisfiedPolicy.Policy, &txn.SiafundInputs[i].SatisfiedPolicy.Signatures); err != nil {
			signed = false
		}
	}

	jc.Encode(SignV2Response{
		Transaction: txn,
		FullySigned: signed,
	})
}

// Handler returns an HTTP handler for the vaultd API.
func Handler(v *vault.Vault, log *zap.Logger) http.Handler {
	a := &api{
		vault: v,
		log:   log,
	}

	return jape.Mux(map[string]jape.Handler{
		"GET /state": a.handleGETState,

		"POST /seeds":          a.handlePOSTSeeds,
		"GET /seeds/:id":       a.handleGETSeedsID,
		"GET /seeds/:id/keys":  a.handleGETSeedsKeys,
		"POST /seeds/:id/keys": a.handlePOSTSeedsKeys,

		"POST /sign":    a.handlePOSTSign,
		"POST /v2/sign": a.handlePOSTSignV2,
	})
}
