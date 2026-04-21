package info

import (
	"context"
	"fmt"
	"text/tabwriter"

	"github.com/urfave/cli/v3"

	"github.com/ekristen/cryptkey/pkg/common"
	"github.com/ekristen/cryptkey/pkg/config"

	"os"
)

func Execute(_ context.Context, cmd *cli.Command) error {
	profileName := cmd.Args().First()
	if profileName == "" {
		profileName = config.DefaultProfile
	}

	profile, err := config.Load(profileName)
	if err != nil {
		return err
	}

	fmt.Printf("Profile:   %s\n", profile.Name)
	fmt.Printf("Threshold: %d of %d\n", profile.Threshold, len(profile.Providers))
	fmt.Println()

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "TYPE\tID")
	fmt.Fprintln(w, "----\t--")
	for _, p := range profile.Providers {
		fmt.Fprintf(w, "%s\t%s\n", p.Type, p.ID)
	}
	return w.Flush()
}

func init() {
	cmd := &cli.Command{
		Name:      "info",
		Usage:     "Show details about a profile",
		ArgsUsage: "[profile]",
		Action:    Execute,
	}
	common.RegisterCommand(cmd)
}
