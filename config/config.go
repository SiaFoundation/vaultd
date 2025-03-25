package config

import (
	"bytes"
	"fmt"
	"os"

	"go.uber.org/zap"
	"gopkg.in/yaml.v3"
)

type (
	// HTTP contains the configuration for the HTTP server.
	HTTP struct {
		Address  string `yaml:"address,omitempty"`
		Password string `yaml:"password,omitempty"`
	}

	// LogFile configures the file output of the logger.
	LogFile struct {
		Enabled bool            `yaml:"enabled,omitempty"`
		Level   zap.AtomicLevel `yaml:"level,omitempty"`
		Format  string          `yaml:"format,omitempty"`
		// Path is the path of the log file.
		Path string `yaml:"path,omitempty"`
	}

	// StdOut configures the standard output of the logger.
	StdOut struct {
		Enabled    bool            `yaml:"enabled,omitempty"`
		Level      zap.AtomicLevel `yaml:"level,omitempty"`
		Format     string          `yaml:"format,omitempty"`
		EnableANSI bool            `yaml:"enableANSI,omitempty"` //nolint:tagliatelle
	}

	// Log contains the configuration for the logger.
	Log struct {
		StdOut StdOut  `yaml:"stdout,omitempty"`
		File   LogFile `yaml:"file,omitempty"`
	}

	// Config contains the configuration for the host.
	Config struct {
		Secret        string `yaml:"secret,omitempty"`
		Directory     string `yaml:"directory,omitempty"`
		AutoOpenWebUI bool   `yaml:"autoOpenWebUI,omitempty"`

		HTTP HTTP `yaml:"http,omitempty"`
		Log  Log  `yaml:"log,omitempty"`
	}
)

// LoadFile loads the configuration from the provided file path.
// If the file does not exist, an error is returned.
// If the file exists but cannot be decoded, the function will attempt
// to upgrade the config file.
func LoadFile(fp string, cfg *Config) error {
	buf, err := os.ReadFile(fp)
	if err != nil {
		return fmt.Errorf("failed to read config file: %w", err)
	}

	r := bytes.NewReader(buf)
	dec := yaml.NewDecoder(r)
	dec.KnownFields(true)

	if err := dec.Decode(cfg); err != nil {
		return fmt.Errorf("failed to decode config file: %w", err)
	}
	return nil
}
