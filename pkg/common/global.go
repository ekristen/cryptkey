package common

import (
	"context"
	"os"

	"github.com/sirupsen/logrus"
	"github.com/urfave/cli/v3"
	"golang.org/x/term"

	"github.com/ekristen/cryptkey/pkg/config"
)

func Flags() []cli.Flag {
	globalFlags := []cli.Flag{
		&cli.StringFlag{
			Name:    "config-dir",
			Usage:   "Override the config directory (default: ~/.config/cryptkey)",
			Sources: cli.EnvVars("CRYPTKEY_CONFIG_DIR"),
		},
		&cli.StringFlag{
			Name:    "log-level",
			Usage:   "Log Level",
			Aliases: []string{"l"},
			Sources: cli.EnvVars("LOG_LEVEL"),
			Value:   "info",
		},
		&cli.BoolFlag{
			Name:    "log-caller",
			Usage:   "log the caller (aka line number and file)",
			Sources: cli.EnvVars("LOG_CALLER"),
			Value:   true,
		},
		&cli.StringFlag{
			Name:    "log-format",
			Usage:   "the log format to use, defaults to auto, options are auto, json, console",
			Sources: cli.EnvVars("LOG_FORMAT"),
			Value:   "auto",
		},
	}

	return globalFlags
}

func Before(ctx context.Context, c *cli.Command) (context.Context, error) {
	// Set custom config directory if provided
	if dir := c.String("config-dir"); dir != "" {
		config.CustomDir = dir
	}

	// Parse log level
	logLevel := c.String("log-level")
	level, err := logrus.ParseLevel(logLevel)
	if err != nil {
		return ctx, err
	}

	// Configure global logrus level
	logrus.SetLevel(level)

	// Set up formatter based on format preference and terminal detection
	stderrFd := int(os.Stderr.Fd()) //nolint:gosec // Fd() fits in int on all supported platforms
	if c.String("log-format") == "json" || (!term.IsTerminal(stderrFd) && c.String("log-format") == "auto") {
		// Use JSON format for non-TTY or when explicitly requested
		logrus.SetFormatter(&logrus.JSONFormatter{
			TimestampFormat: "2006-01-02T15:04:05Z07:00",
		})
	} else {
		// Use custom console format with colors for TTY (similar to zerolog)
		logrus.SetFormatter(&ConsoleFormatter{
			TimestampFormat: "3:04:05PM",
			NoColor:         false,
		})
	}

	// Configure output
	logrus.SetOutput(os.Stderr)

	// Configure caller information
	if c.Bool("log-caller") {
		logrus.SetReportCaller(true)
	}

	return ctx, nil
}
