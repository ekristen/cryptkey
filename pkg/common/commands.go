package common

import (
	"context"
	"sort"

	"github.com/urfave/cli/v3"
)

var commands = make(map[string][]*cli.Command, 0)

// RegisterSubcommand allows you to register a command under a group
func RegisterSubcommand(group string, command *cli.Command) {
	commands[group] = append(commands[group], command)
}

// GetSubcommands retrieves all commands assigned to a group
func GetSubcommands(group string) []*cli.Command {
	return commands[group]
}

// RegisterCommand -- allows you to register a command under the main group
func RegisterCommand(command *cli.Command) {
	// Our commands are leaves that take positional arguments (profile names,
	// etc.), not sub-command dispatchers. Without this, urfave/cli v3 treats
	// `cryptkey <cmd> <arg> --help` as a request to show help for a sub-command
	// named <arg>, which always fails with "No help topic for '<arg>'". Route
	// those lookups into a re-print of the command's own help so --help works
	// regardless of whether a positional is present.
	if command.CommandNotFound == nil {
		command.CommandNotFound = func(_ context.Context, c *cli.Command, _ string) {
			cli.HelpPrinter(c.Root().Writer, cli.CommandHelpTemplate, c)
		}
	}
	commands["_main_"] = append(commands["_main_"], command)
}

// GetCommands -- retrieves all commands assigned to the main group, sorted by name.
func GetCommands() []*cli.Command {
	cmds := commands["_main_"]
	sort.Slice(cmds, func(i, j int) bool {
		return cmds[i].Name < cmds[j].Name
	})
	return cmds
}
