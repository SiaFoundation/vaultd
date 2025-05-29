package chain

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"go.sia.tech/core/consensus"
	"go.sia.tech/coreutils/threadgroup"
	"go.uber.org/zap"
)

// An Option is a functional option for configuring a Manager
type Option func(*Manager)

var client = &http.Client{
	Timeout: 10 * time.Second,
}

type Manager struct {
	tg  *threadgroup.ThreadGroup
	log *zap.Logger

	baseURL      string
	pollInterval time.Duration

	mu sync.Mutex
	cs consensus.State
}

// getNetwork retrieves the network information from the explorer.
// This only needs to be called once, as the network information is cached.
// It is assumed that the caller will hold the mutex before calling this method.
func getNetwork(ctx context.Context, baseURL string) (network consensus.Network, err error) {
	err = makeGETRequest(ctx, baseURL+"/consensus/network", &network)
	return
}

// getConsensusState retrieves the current consensus state from the explorer.
func getConsensusState(ctx context.Context, network *consensus.Network, baseURL string) (cs consensus.State, err error) {
	err = makeGETRequest(ctx, baseURL+"/consensus/state", &cs)
	cs.Network = network
	return
}

// pollConsensusState periodically polls the explorer for the latest consensus state.
// It should be started in a goroutine and will run until the chain is closed.
func (m *Manager) pollConsensusState() {
	log := m.log.Named("poll")
	ctx, cancel, err := m.tg.AddContext(context.Background())
	if err != nil {
		log.Debug("failed to add context for consensus state polling", zap.Error(err))
		return
	}
	defer cancel()

	ticker := time.NewTicker(m.pollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		// reuse existing network
		cs, err := getConsensusState(ctx, m.cs.Network, m.baseURL)
		if err != nil {
			fmt.Printf("failed to get consensus state: %v\n", err)
			continue
		}
		m.mu.Lock()
		if m.cs.Index != cs.Index {
			log.Debug("consensus state updated", zap.Stringer("tip", cs.Index), zap.Stringer("prev", m.cs.Index))
		}
		m.cs = cs
		m.mu.Unlock()

	}
}

// TipState retrieves the current tip state
func (m *Manager) TipState(ctx context.Context) (consensus.State, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.cs.Network == nil {
		network, err := getNetwork(ctx, m.baseURL)
		if err != nil {
			return consensus.State{}, fmt.Errorf("failed to get network: %w", err)
		}
		cs, err := getConsensusState(ctx, &network, m.baseURL)
		if err != nil {
			return consensus.State{}, fmt.Errorf("failed to get consensus state: %w", err)
		}
		m.cs = cs
		go m.pollConsensusState()
	}
	return m.cs, nil
}

// Close stops the chain's thread group and cleans up resources.
func (m *Manager) Close() error {
	m.tg.Stop()
	return nil
}

func makeGETRequest(ctx context.Context, url string, obj any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	} else if err := json.NewDecoder(resp.Body).Decode(obj); err != nil {
		return fmt.Errorf("failed to decode response: %w", err)
	}
	return nil
}

// WithLog sets the logger for the chain.
func WithLog(log *zap.Logger) Option {
	return func(m *Manager) {
		m.log = log
	}
}

// WithPollInterval sets the interval for polling the consensus state.
func WithPollInterval(interval time.Duration) Option {
	return func(m *Manager) {
		m.pollInterval = interval
	}
}

// New creates a new Explorer instance with the given base URL.
func New(baseURL string, opts ...Option) *Manager {
	m := &Manager{
		tg:           threadgroup.New(),
		log:          zap.NewNop(),
		baseURL:      baseURL,
		pollInterval: time.Minute,
	}
	for _, opt := range opts {
		opt(m)
	}
	return m
}
