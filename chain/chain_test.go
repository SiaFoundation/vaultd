package chain

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"

	"go.sia.tech/core/consensus"
	"go.sia.tech/core/types"
	"go.sia.tech/coreutils"
	"go.sia.tech/coreutils/testutil"
)

func startConsensusServer(tb testing.TB) (string, func(consensus.State)) {
	tb.Helper()

	l, err := net.Listen("tcp", ":0")
	if err != nil {
		tb.Fatalf("failed to start consensus server: %v", err)
	}
	tb.Cleanup(func() { l.Close() })

	var mu sync.Mutex
	var cs consensus.State
	updateConsensusFunc := func(newState consensus.State) {
		mu.Lock()
		cs = newState
		mu.Unlock()
	}

	s := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodGet {
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			mu.Lock()
			defer mu.Unlock()
			switch r.URL.Path {
			case "/consensus/network":
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				if err := json.NewEncoder(w).Encode(cs.Network); err != nil {
					panic(err)
				}
			case "/consensus/state":
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				if err := json.NewEncoder(w).Encode(cs); err != nil {
					panic(err)
				}
			default:
				http.NotFound(w, r)
			}
		}),
	}
	tb.Cleanup(func() { s.Close() })
	go func() {
		if err := s.Serve(l); err != nil && !errors.Is(err, http.ErrServerClosed) {
			panic(err)
		}
	}()
	return "http://" + l.Addr().String(), updateConsensusFunc
}

func TestChainPolling(t *testing.T) {
	addr, updateFn := startConsensusServer(t)

	n, genesis := testutil.Network()
	cs, _ := consensus.ApplyBlock(n.GenesisState(), genesis, consensus.V1BlockSupplement{Transactions: make([]consensus.V1TransactionSupplement, len(genesis.Transactions))}, time.Time{})
	updateFn(cs)

	m := New(addr, WithPollInterval(100*time.Millisecond))

	tip, err := m.TipState(context.Background())
	if err != nil {
		t.Fatalf("failed to get initial tip state: %v", err)
	} else if tip.Index != cs.Index {
		t.Fatalf("expected initial tip index %v, got %v", cs.Index, tip.Index)
	}

	b := types.Block{
		ParentID:  genesis.ID(),
		Timestamp: time.Now(),
		MinerPayouts: []types.SiacoinOutput{
			{Address: types.VoidAddress, Value: cs.BlockReward()},
		},
	}
	if !coreutils.FindBlockNonce(cs, &b, time.Minute) {
		t.Fatal("failed to find block nonce in initial consensus state")
	}
	cs, _ = consensus.ApplyBlock(cs, b, consensus.V1BlockSupplement{Transactions: make([]consensus.V1TransactionSupplement, len(b.Transactions))}, time.Now())
	updateFn(cs)

	time.Sleep(200 * time.Millisecond) // wait for polling to catch up

	tip, err = m.TipState(context.Background())
	if err != nil {
		t.Fatal("failed to get updated tip state:", err)
	} else if tip.Index != cs.Index {
		t.Fatalf("expected updated tip index %v, got %v", cs.Index, tip.Index)
	}
}
