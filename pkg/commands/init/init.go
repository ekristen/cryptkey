package cmdinit

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/sirupsen/logrus"
	"github.com/urfave/cli/v3"
	"golang.org/x/term"

	tea "charm.land/bubbletea/v2"

	"github.com/ekristen/cryptkey/pkg/common"
	"github.com/ekristen/cryptkey/pkg/config"
	"github.com/ekristen/cryptkey/pkg/enrollment"
	"github.com/ekristen/cryptkey/pkg/provider"
	"github.com/ekristen/cryptkey/pkg/tui"
)

func Execute(ctx context.Context, cmd *cli.Command) error {
	profileName := cmd.Args().First()
	if profileName == "" {
		profileName = config.DefaultProfile
	}

	threshold := cmd.Int("threshold")
	force := cmd.Bool("force")
	noTUI := cmd.Bool("no-tui")
	addProviders := cmd.StringSlice("add")

	// Apply FIDO2 UV preference to context
	if v := cmd.String("fido2-uv"); v != "" {
		switch v {
		case "discouraged", "preferred", "required":
			ctx = context.WithValue(ctx, provider.CtxFIDO2UV, v)
		default:
			return errors.New("--fido2-uv must be discouraged, preferred, or required")
		}
	}

	// Apply Argon2id parameter overrides to context
	if v := cmd.Int("argon-time"); v > 0 {
		ctx = context.WithValue(ctx, provider.CtxArgonTime, uint32(v)) //nolint:gosec // CLI flag values are bounded by reasonable Argon2 ranges
	}
	if v := cmd.Int("argon-memory"); v > 0 {
		ctx = context.WithValue(ctx, provider.CtxArgonMemory, uint32(v)) //nolint:gosec // CLI flag values are bounded by reasonable Argon2 ranges
	}
	if v := cmd.Int("argon-threads"); v > 0 {
		ctx = context.WithValue(ctx, provider.CtxArgonThreads, uint8(v)) //nolint:gosec // CLI flag values are bounded by reasonable Argon2 ranges
	}

	exists, err := config.Exists(profileName)
	if err != nil {
		return err
	}
	if exists && !force {
		return fmt.Errorf("profile %q already exists (use --force to overwrite)", profileName)
	}

	// If all providers specified via --add, skip interactive entirely
	if len(addProviders) >= threshold {
		return execFlagDriven(ctx, profileName, threshold, addProviders)
	}

	// TUI mode: default when stderr is a TTY and --no-tui not set
	isTTY := term.IsTerminal(int(os.Stderr.Fd())) //nolint:gosec // Fd() fits in int on all supported platforms
	if isTTY && !noTUI {
		return execTUI(ctx, profileName, threshold)
	}

	// Simple interactive mode
	return execSimple(ctx, profileName, threshold)
}

func execTUI(ctx context.Context, profileName string, threshold int) error {
	m := tui.New(ctx, profileName, threshold)
	p := tea.NewProgram(m, tea.WithOutput(os.Stderr))

	finalModel, err := p.Run()
	if err != nil {
		return fmt.Errorf("tui: %w", err)
	}

	final := finalModel.(tui.Model)
	if final.Err() != nil {
		return final.Err()
	}
	if !final.Completed() {
		return errors.New("enrollment canceled")
	}

	path, _ := config.Path(profileName)
	fmt.Fprintf(os.Stderr, "Profile written to %s\n", path)
	fmt.Fprintf(os.Stderr, "Enrolled %d providers with threshold %d\n", len(final.Enrollments()), threshold)
	printRecoveryWarning(threshold, final.Enrollments())

	return nil
}

//nolint:gocyclo,funlen // sequential setup function; refactoring would harm readability
func execSimple(ctx context.Context, profileName string, threshold int) error {
	ttyFile, err := os.Open("/dev/tty")
	if err != nil {
		ttyFile = os.Stdin
	} else {
		defer ttyFile.Close()
	}
	scanner := bufio.NewScanner(ttyFile)
	providers := provider.All()

	fmt.Fprintf(os.Stderr, "\nInitializing profile %q with threshold %d\n\n", profileName, threshold)

	var enrollments []enrollment.Enrollment

	for {
		fmt.Fprintln(os.Stderr, "Available providers:")
		for i, p := range providers {
			fmt.Fprintf(os.Stderr, "  [%d] %s — %s\n", i+1, p.Type(), p.Description())
		}
		fmt.Fprintln(os.Stderr)

		if len(enrollments) >= threshold {
			fmt.Fprint(os.Stderr, "Select provider (number), or 'done' to finish: ")
		} else {
			remaining := threshold - len(enrollments)
			fmt.Fprintf(os.Stderr, "Select provider (number) [%d more needed]: ", remaining)
		}

		if !scanner.Scan() {
			break
		}
		input := strings.TrimSpace(scanner.Text())

		if strings.EqualFold(input, "done") {
			if len(enrollments) < threshold {
				fmt.Fprintf(os.Stderr, "Need at least %d providers (have %d)\n", threshold, len(enrollments))
				continue
			}
			break
		}

		idx, err := strconv.Atoi(input)
		if err != nil || idx < 1 || idx > len(providers) {
			fmt.Fprintln(os.Stderr, "Invalid selection")
			continue
		}

		p := providers[idx-1]
		id := defaultID(p.Type(), enrollments)

		fmt.Fprintf(os.Stderr, "Provider ID [%s]: ", id)
		if scanner.Scan() {
			if t := strings.TrimSpace(scanner.Text()); t != "" {
				id = t
			}
		}

		// Check duplicate
		dup := false
		for _, e := range enrollments {
			if e.ID == id {
				fmt.Fprintf(os.Stderr, "ID %q already in use\n", id)
				dup = true
				break
			}
		}
		if dup {
			continue
		}

		e, err := enrollment.EnrollProvider(ctx, p, id)
		if err != nil {
			logrus.WithError(err).WithField("provider", p.Type()).Error("enrollment failed")
			fmt.Fprintln(os.Stderr)
			continue
		}

		enrollments = append(enrollments, *e)
		fmt.Fprintf(os.Stderr, "Enrolled %q (%d total)\n\n", id, len(enrollments))
	}

	if len(enrollments) < threshold {
		return fmt.Errorf("not enough providers enrolled (%d < threshold %d)", len(enrollments), threshold)
	}

	if err := enrollment.BuildProfile(profileName, threshold, enrollments); err != nil {
		return err
	}

	path, _ := config.Path(profileName)
	fmt.Fprintf(os.Stderr, "\nProfile written to %s\n", path)
	fmt.Fprintf(os.Stderr, "Enrolled %d providers with threshold %d\n", len(enrollments), threshold)
	printRecoveryWarning(threshold, enrollments)
	return nil
}

// execFlagDriven handles fully flag-driven enrollment (no interactive menus).
// --add values are "type" or "type:id" (e.g. "fido2", "passphrase:recovery").
func execFlagDriven(ctx context.Context, profileName string, threshold int, addProviders []string) error {
	var enrollments []enrollment.Enrollment

	for _, spec := range addProviders {
		typeName, id := parseAddSpec(spec)

		p, ok := provider.Get(typeName)
		if !ok {
			return fmt.Errorf("unknown provider type %q", typeName)
		}

		if id == "" {
			id = defaultID(typeName, enrollments)
		}

		fmt.Fprintf(os.Stderr, "Enrolling %s as %q...\n", typeName, id)

		e, err := enrollment.EnrollProvider(ctx, p, id)
		if err != nil {
			return fmt.Errorf("enroll %q: %w", id, err)
		}

		enrollments = append(enrollments, *e)
		fmt.Fprintf(os.Stderr, "Enrolled %q\n\n", id)
	}

	if err := enrollment.BuildProfile(profileName, threshold, enrollments); err != nil {
		return err
	}

	path, _ := config.Path(profileName)
	fmt.Fprintf(os.Stderr, "Profile written to %s\n", path)
	fmt.Fprintf(os.Stderr, "Enrolled %d providers with threshold %d\n", len(enrollments), threshold)
	printRecoveryWarning(threshold, enrollments)
	return nil
}

func parseAddSpec(spec string) (typeName, id string) {
	if idx := strings.IndexByte(spec, ':'); idx >= 0 {
		return spec[:idx], spec[idx+1:]
	}
	return spec, ""
}

func defaultID(typeName string, enrollments []enrollment.Enrollment) string {
	count := 1
	for _, e := range enrollments {
		if e.Provider.Type() == typeName {
			count++
		}
	}
	return fmt.Sprintf("%s-%d", typeName, count)
}

func printRecoveryWarning(threshold int, enrollments []enrollment.Enrollment) {
	if w := enrollment.RecoveryWarning(threshold, enrollments); w != "" {
		fmt.Fprintf(os.Stderr, "\n%s\n", w)
	}
}

func init() {
	cmd := &cli.Command{
		Name:      "init",
		Usage:     "Enroll providers and create a new profile",
		ArgsUsage: "[profile]",
		Flags: []cli.Flag{
			&cli.IntFlag{
				Name:    "threshold",
				Aliases: []string{"t"},
				Usage:   "Minimum providers needed to derive key",
				Value:   2,
			},
			&cli.BoolFlag{
				Name:  "force",
				Usage: "Overwrite existing profile",
			},
			&cli.BoolFlag{
				Name:  "no-tui",
				Usage: "Use simple interactive mode instead of TUI",
			},
			&cli.StringSliceFlag{
				Name:    "add",
				Aliases: []string{"a"},
				Usage:   "Add a provider (type or type:id, e.g. fido2, passphrase:recovery)",
			},
			&cli.StringFlag{
				Name:  "fido2-uv",
				Usage: "FIDO2 user verification: discouraged, preferred, required (default: preferred)",
			},
			&cli.IntFlag{
				Name:  "argon-time",
				Usage: "Argon2id iterations for passphrase and recovery providers (default 3)",
			},
			&cli.IntFlag{
				Name: "argon-memory",
				Usage: "Argon2id memory in KiB for passphrase and recovery providers " +
					"(default 262144 = 256 MiB; 19456 = 19 MiB is the OWASP minimum floor)",
			},
			&cli.IntFlag{
				Name:  "argon-threads",
				Usage: "Argon2id parallelism for passphrase and recovery providers (default 4)",
			},
		},
		Action: Execute,
	}
	common.RegisterCommand(cmd)
}
