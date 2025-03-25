package sqlite

import (
	"time"

	"go.uber.org/zap"
)

type (
	options struct {
		maxRetryAttempts int
		busyTimeout      time.Duration
		log              *zap.Logger
	}

	// An Option is a functional option for configuring a Store.
	Option func(*options)
)

// WithMaxRetryAttempts sets the maximum number of times a transaction will be
// retried if it fails due to a busy error.
func WithMaxRetryAttempts(maxRetryAttempts int) Option {
	return func(o *options) {
		o.maxRetryAttempts = maxRetryAttempts
	}
}

// WithBusyTimeout sets the maximum amount of time a transaction will wait for a
// lock before returning an error.
func WithBusyTimeout(busyTimeout time.Duration) Option {
	return func(o *options) {
		o.busyTimeout = busyTimeout
	}
}

// WithLogger sets the logger used by the Store.
func WithLogger(log *zap.Logger) Option {
	return func(o *options) {
		o.log = log
	}
}
