package list

import (
	"context"
	"fmt"

	"github.com/urfave/cli/v3"

	"github.com/ekristen/cryptkey/pkg/common"
	"github.com/ekristen/cryptkey/pkg/config"
)

func Execute(_ context.Context, _ *cli.Command) error {
	names, err := config.List()
	if err != nil {
		return err
	}

	if len(names) == 0 {
		fmt.Println("No profiles found.")
		return nil
	}

	for _, name := range names {
		fmt.Println(name)
	}
	return nil
}

func init() {
	cmd := &cli.Command{
		Name:   "list",
		Usage:  "List available profiles",
		Action: Execute,
	}
	common.RegisterCommand(cmd)
}
