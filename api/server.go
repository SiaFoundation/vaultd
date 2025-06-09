package api

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"net/http"
	"runtime"
	"strings"
	"time"

	"go.sia.tech/core/consensus"
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
	// A Chain is an interface that provides access to the current
	// consensus state of the blockchain.
	Chain interface {
		TipState(ctx context.Context) (consensus.State, error)
	}

	api struct {
		vault *vault.Vault
		log   *zap.Logger
		chain Chain
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

func (a *api) handleGETSeeds(jc jape.Context) {
	var (
		limit  = 100
		offset = 0
	)

	if jc.DecodeForm("limit", &limit) != nil {
		return
	} else if jc.DecodeForm("offset", &offset) != nil {
		return
	}

	if limit < 1 || limit > 500 {
		jc.Error(errors.New("limit must be between 1 and 500"), http.StatusBadRequest)
		return
	} else if offset < 0 {
		jc.Error(errors.New("offset must be non-negative"), http.StatusBadRequest)
		return
	}

	seeds, err := a.vault.Seeds(limit, offset)
	if err != nil {
		jc.Error(err, http.StatusInternalServerError)
		return
	}
	jc.Encode(SeedsResponse{
		Seeds: seeds,
	})
}

func (a *api) handlePOSTSeeds(jc jape.Context) {
	var req AddSeedRequest
	if err := jc.Decode(&req); err != nil {
		return
	}

	var seed [32]byte
	defer clear(seed[:])
	switch len(strings.Fields(req.Phrase)) {
	case 28, 29:
		if err := siad.SeedFromPhrase(&seed, req.Phrase); err != nil {
			jc.Error(err, http.StatusBadRequest)
			return
		}
	case 12:
		if err := wallet.SeedFromPhrase(&seed, req.Phrase); err != nil {
			jc.Error(err, http.StatusBadRequest)
			return
		}
	default:
		jc.Error(errors.New("invalid phrase length, must be BIP39 12 word seed or 28 word Sia seed"), http.StatusBadRequest)
		return
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

func (a *api) getConsensusState(ctx context.Context, state *consensus.State, network *consensus.Network) (consensus.State, error) {
	if state != nil && network != nil {
		cs := *state
		cs.Network = network
		return cs, nil
	} else if state == nil && network == nil {
		a.log.Debug("getting consensus state from chain")
		return a.chain.TipState(ctx)
	} else if state == nil {
		return consensus.State{}, errors.New("state must be provided if network is provided")
	}
	return consensus.State{}, errors.New("network must be provided if state is provided")
}

func (a *api) handlePOSTSign(jc jape.Context) {
	var req SignRequest
	if err := jc.Decode(&req); err != nil {
		return
	}

	cs, err := a.getConsensusState(jc.Request.Context(), req.State, req.Network)
	if err != nil {
		jc.Error(err, http.StatusBadRequest)
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

	cs, err := a.getConsensusState(jc.Request.Context(), req.State, req.Network)
	if err != nil {
		jc.Error(err, http.StatusBadRequest)
		return
	}

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

func (a *api) handlePOSTBlindSign(jc jape.Context) {
	var req BlindSignRequest
	if err := jc.Decode(&req); err != nil {
		return
	}

	sig, err := a.vault.Sign(req.PublicKey, req.SigHash)
	if errors.Is(err, vault.ErrNotFound) {
		jc.Error(err, http.StatusNotFound)
		return
	} else if err != nil {
		jc.Error(err, http.StatusInternalServerError)
		return
	}
	jc.Encode(BlindSignResponse{Signature: sig})
}

func (a *api) handlePOSTUnlock(jc jape.Context) {
	var req UnlockRequest
	if err := jc.Decode(&req); err != nil {
		return
	}

	switch err := a.vault.Unlock(req.Secret); err {
	case nil:
		jc.Encode(nil)
	case vault.ErrUnlocked:
		jc.Error(err, http.StatusBadRequest)
	case vault.ErrIncorrectSecret:
		jc.Error(err, http.StatusUnauthorized)
	default:
		jc.Error(err, http.StatusInternalServerError)
	}
}

func (a *api) handlePUTLock(jc jape.Context) {
	a.vault.Lock()
	jc.Encode(nil)
}

// Handler returns an HTTP handler for the vaultd API.
func Handler(c Chain, v *vault.Vault, log *zap.Logger) http.Handler {
	a := &api{
		chain: c,
		vault: v,
		log:   log,
	}
	return jape.Mux(map[string]jape.Handler{
		"GET /state": a.handleGETState,

		"GET /seeds":           a.handleGETSeeds,
		"POST /seeds":          a.handlePOSTSeeds,
		"GET /seeds/:id":       a.handleGETSeedsID,
		"GET /seeds/:id/keys":  a.handleGETSeedsKeys,
		"POST /seeds/:id/keys": a.handlePOSTSeedsKeys,

		"POST /unlock": a.handlePOSTUnlock,
		"PUT /lock":    a.handlePUTLock,

		"POST /sign":    a.handlePOSTSign,
		"POST /v2/sign": a.handlePOSTSignV2,

		"POST /blind/sign": a.handlePOSTBlindSign,
	})
}
