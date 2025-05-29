package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"path/filepath"
	"time"

	"go.sia.tech/jape"
	"go.sia.tech/vaultd/api"
	"go.sia.tech/vaultd/chain"
	"go.sia.tech/vaultd/persist/sqlite"
	"go.sia.tech/vaultd/vault"
	"go.uber.org/zap"
)

// run runs the vault daemon. It blocks until the context is canceled or
// an error occurs.
func run(ctx context.Context, log *zap.Logger) error {
	httpListener, err := net.Listen("tcp", cfg.HTTP.Address)
	if err != nil {
		return fmt.Errorf("failed to listen on %q: %w", cfg.HTTP.Address, err)
	}
	defer httpListener.Close()

	store, err := sqlite.OpenDatabase(filepath.Join(cfg.Directory, "vaultd.sqlite3"),
		sqlite.WithLogger(log.Named("sqlite3")),
		sqlite.WithBusyTimeout(15*time.Second))
	if err != nil {
		return fmt.Errorf("failed to open wallet database: %w", err)
	}
	defer store.Close()

	vault := vault.New(store)
	defer vault.Close()

	if cfg.Secret != "" {
		if err := vault.Unlock(cfg.Secret); err != nil {
			return fmt.Errorf("failed to unlock vault: %w", err)
		}
	}

	var manager *chain.Manager
	if cfg.Explorer.URL != "" {
		manager = chain.New(cfg.Explorer.URL, chain.WithLog(log.Named("chain")))
	} else {
		switch cfg.Explorer.Network {
		case "mainnet":
			manager = chain.New("https://api.siascan.com", chain.WithLog(log.Named("chain")))
		case "zen":
			manager = chain.New("https://api.siascan.com/zen", chain.WithLog(log.Named("chain")))
		default:
			return fmt.Errorf("unknown explorer network %q", cfg.Explorer.Network)
		}
	}

	server := &http.Server{
		ReadTimeout:  5 * time.Second,
		WriteTimeout: time.Minute,
		Handler:      jape.BasicAuth(cfg.HTTP.Password)(api.Handler(manager, vault, log.Named("api"))),
	}
	defer server.Close()
	go func() {
		if err := server.Serve(httpListener); !errors.Is(err, http.ErrServerClosed) {
			log.Error("HTTP server failed", zap.Error(err))
		}
	}()

	log.Info("vaultd started", zap.String("http", cfg.HTTP.Address))
	<-ctx.Done()
	log.Debug("shutting down")
	time.AfterFunc(10*time.Second, func() {
		log.Panic("shutdown took too long")
	})
	return nil
}
