package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"syscall"
	"time"

	"go.sia.tech/seedvault/config"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"lukechampine.com/flagg"
	"lukechampine.com/upnp"
)

const (
	apiPasswordEnvVar = "VAULTD_API_PASSWORD"
	configFileEnvVar  = "VAULTD_CONFIG_FILE"
	dataDirEnvVar     = "VAULTD_DATA_DIR"
	secretEnvVar      = "VAULTD_SECRET"
)

func tryConfigPaths() []string {
	if str := os.Getenv(configFileEnvVar); str != "" {
		return []string{str}
	}

	paths := []string{
		"vaultd.yml",
	}
	if str := os.Getenv(dataDirEnvVar); str != "" {
		paths = append(paths, filepath.Join(str, "vaultd.yml"))
	}

	switch runtime.GOOS {
	case "windows":
		paths = append(paths, filepath.Join(os.Getenv("APPDATA"), "vaultd", "vaultd.yml"))
	case "darwin":
		paths = append(paths, filepath.Join(os.Getenv("HOME"), "Library", "Application Support", "vaultd", "vaultd.yml"))
	case "linux", "freebsd", "openbsd":
		paths = append(paths,
			filepath.Join(string(filepath.Separator), "etc", "vaultd", "vaultd.yml"),
			filepath.Join(string(filepath.Separator), "var", "lib", "vaultd", "vaultd.yml"), // old default for the Linux service
		)
	}
	return paths
}

func defaultDataDirectory(fp string) string {
	// use the provided path if it's not empty
	if fp != "" {
		return fp
	}

	// check for databases in the current directory
	if _, err := os.Stat("vaultd.sqlite3"); err == nil {
		return "."
	}

	// default to the operating system's application directory
	switch runtime.GOOS {
	case "windows":
		return filepath.Join(os.Getenv("APPDATA"), "vaultd")
	case "darwin":
		return filepath.Join(os.Getenv("HOME"), "Library", "Application Support", "vaultd")
	case "linux", "freebsd", "openbsd":
		return filepath.Join(string(filepath.Separator), "var", "lib", "vaultd")
	default:
		return "."
	}
}

func setupUPNP(ctx context.Context, port uint16, log *zap.Logger) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	d, err := upnp.Discover(ctx)
	if err != nil {
		return "", fmt.Errorf("couldn't discover UPnP router: %w", err)
	} else if !d.IsForwarded(port, "TCP") {
		if err := d.Forward(uint16(port), "TCP", "vaultd"); err != nil {
			log.Debug("couldn't forward port", zap.Error(err))
		} else {
			log.Debug("upnp: forwarded p2p port", zap.Uint16("port", port))
		}
	}
	return d.ExternalIP()
}

// checkFatalError prints an error message to stderr and exits with a 1 exit code. If err is nil, this is a no-op.
func checkFatalError(context string, err error) {
	if err == nil {
		return
	}
	os.Stderr.WriteString(fmt.Sprintf("%s: %s\n", context, err))
	os.Exit(1)
}

// tryLoadConfig tries to load the config file. It will try multiple locations
// based on GOOS starting with PWD/vaultd.yml. If the file does not exist, it will
// try the next location. If an error occurs while loading the file, it will
// print the error and exit. If the config is successfully loaded, the path to
// the config file is returned.
func tryLoadConfig() string {
	for _, fp := range tryConfigPaths() {
		if err := config.LoadFile(fp, &cfg); err == nil {
			return fp
		} else if !errors.Is(err, os.ErrNotExist) {
			checkFatalError("failed to load config file", err)
		}
	}
	return ""
}

// jsonEncoder returns a zapcore.Encoder that encodes logs as JSON intended for
// parsing.
func jsonEncoder() zapcore.Encoder {
	cfg := zap.NewProductionEncoderConfig()
	cfg.EncodeTime = zapcore.RFC3339TimeEncoder
	cfg.TimeKey = "timestamp"
	return zapcore.NewJSONEncoder(cfg)
}

// humanEncoder returns a zapcore.Encoder that encodes logs as human-readable
// text.
func humanEncoder(showColors bool) zapcore.Encoder {
	cfg := zap.NewProductionEncoderConfig()
	cfg.EncodeTime = zapcore.RFC3339TimeEncoder
	cfg.EncodeDuration = zapcore.StringDurationEncoder

	if showColors {
		cfg.EncodeLevel = zapcore.CapitalColorLevelEncoder
	} else {
		cfg.EncodeLevel = zapcore.CapitalLevelEncoder
	}

	cfg.StacktraceKey = ""
	cfg.CallerKey = ""
	return zapcore.NewConsoleEncoder(cfg)
}

var cfg = config.Config{
	Secret:    os.Getenv(secretEnvVar),
	Directory: os.Getenv(dataDirEnvVar),
	HTTP: config.HTTP{
		Address:  "localhost:9980",
		Password: os.Getenv(apiPasswordEnvVar),
	},
	Syncer: config.Syncer{
		Address:   ":9981",
		Bootstrap: true,
	},
	Consensus: config.Consensus{
		Network: "mainnet",
	},
	Log: config.Log{
		File: config.LogFile{
			Enabled: true,
			Format:  "human",
			Level:   zap.NewAtomicLevelAt(zap.InfoLevel),
		},
		StdOut: config.StdOut{
			Enabled:    true,
			Format:     "human",
			Level:      zap.NewAtomicLevelAt(zap.InfoLevel),
			EnableANSI: runtime.GOOS != "windows",
		},
	},
}

func main() {
	// attempt to load the config file, command line flags will override any
	// values set in the config file
	tryLoadConfig()
	// set the data directory to the default if it is not set
	cfg.Directory = defaultDataDirectory(cfg.Directory)

	rootCmd := flagg.Root
	rootCmd.StringVar(&cfg.Consensus.Network, "network", cfg.Consensus.Network, "the network to connect to")
	rootCmd.Usage = flagg.SimpleUsage(rootCmd, ``)

	cmd := flagg.Parse(flagg.Tree{
		Cmd: rootCmd,
	})

	switch cmd {
	case rootCmd:
		if len(cmd.Args()) != 0 {
			cmd.Usage()
			return
		}

		ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM, syscall.SIGKILL)
		defer cancel()

		if cfg.Directory != "" {
			checkFatalError("failed to create data directory", os.MkdirAll(cfg.Directory, 0700))
		}

		if cfg.HTTP.Password == "" {
			checkFatalError("missing password", errors.New("HTTP auth password must be set using ENV variable or config file"))
		} else if cfg.Secret == "" {
			checkFatalError("missing secret", errors.New("secret must be set using ENV variable or config file"))
		}

		var logCores []zapcore.Core
		if cfg.Log.StdOut.Enabled {
			var encoder zapcore.Encoder
			switch cfg.Log.StdOut.Format {
			case "json":
				encoder = jsonEncoder()
			default: // stdout defaults to human
				encoder = humanEncoder(cfg.Log.StdOut.EnableANSI)
			}

			// create the stdout logger
			logCores = append(logCores, zapcore.NewCore(encoder, zapcore.Lock(os.Stdout), cfg.Log.StdOut.Level))
		}

		if cfg.Log.File.Enabled {
			// normalize log path
			if cfg.Log.File.Path == "" {
				cfg.Log.File.Path = filepath.Join(cfg.Directory, "vaultd.log")
			}

			// configure file logging
			var encoder zapcore.Encoder
			switch cfg.Log.File.Format {
			case "human":
				encoder = humanEncoder(false) // disable colors in file log
			default: // log file defaults to JSON
				encoder = jsonEncoder()
			}

			fileWriter, closeFn, err := zap.Open(cfg.Log.File.Path)
			checkFatalError("failed to open log file", err)
			defer closeFn()

			// create the file logger
			logCores = append(logCores, zapcore.NewCore(encoder, zapcore.Lock(fileWriter), cfg.Log.File.Level))
		}

		var log *zap.Logger
		if len(logCores) == 1 {
			log = zap.New(logCores[0], zap.AddCaller())
		} else {
			log = zap.New(zapcore.NewTee(logCores...), zap.AddCaller())
		}
		defer log.Sync()

		// redirect stdlib log to zap
		zap.RedirectStdLog(log.Named("stdlib"))

		checkFatalError("failed to run node", run(ctx, log))
	default:
		cmd.Usage()
	}
}
