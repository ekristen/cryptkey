package main

import (
	"context"
	"os"

	"github.com/rancher/wrangler/pkg/signals"
	"github.com/sirupsen/logrus"
	"github.com/urfave/cli/v3"

	"github.com/ekristen/cryptkey/pkg/common"

	_ "github.com/ekristen/cryptkey/pkg/commands/derive"
	_ "github.com/ekristen/cryptkey/pkg/commands/info"
	_ "github.com/ekristen/cryptkey/pkg/commands/init"
	_ "github.com/ekristen/cryptkey/pkg/commands/list"
	_ "github.com/ekristen/cryptkey/pkg/commands/rekey"

	_ "github.com/ekristen/cryptkey/pkg/provider/fido2"
	_ "github.com/ekristen/cryptkey/pkg/provider/passkey"
	_ "github.com/ekristen/cryptkey/pkg/provider/passphrase"
	_ "github.com/ekristen/cryptkey/pkg/provider/piv"
	_ "github.com/ekristen/cryptkey/pkg/provider/recovery"
	_ "github.com/ekristen/cryptkey/pkg/provider/sshagent"
	_ "github.com/ekristen/cryptkey/pkg/provider/sshkey"
	_ "github.com/ekristen/cryptkey/pkg/provider/tpm"
)

func main() {
	var exitCode int

	func() {
		defer func() {
			if r := recover(); r != nil {
				// log panics using logrus and set exit code
				logrus.WithField("panic", r).Error("panic recovered")
				exitCode = 1
			}
		}()

		app := &cli.Command{
			Name:    common.AppVersion.Name,
			Usage:   common.AppVersion.Name,
			Version: common.AppVersion.Summary,
			Authors: []any{
				"Erik Kristensen <erik@erikkristensen.com>",
			},
			Commands: common.GetCommands(),
			CommandNotFound: func(ctx context.Context, command *cli.Command, s string) {
				logrus.WithField("command", s).Error("command not found")
			},
			EnableShellCompletion: true,
			Before:                common.Before,
			Flags:                 common.Flags(),
		}

		ctx := signals.SetupSignalContext()
		if err := app.Run(ctx, os.Args); err != nil {
			logrus.WithError(err).Error("fatal error")
			exitCode = 1
		}
	}()

	if exitCode != 0 {
		os.Exit(exitCode)
	}
}
