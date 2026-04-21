// Package rekey implements the `cryptkey rekey` command, which rebuilds a
// profile's Shamir share set under a new (n', t') and provider list while
// preserving the existing master key and output salt.
//
// Preserving the master key + output salt means every key already derived
// from this profile (including age identities, ed25519 keys, AEAD keys
// stored elsewhere) continues to validate against the new profile. What
// changes is the set of providers that can unlock it.
package rekey

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	tea "charm.land/bubbletea/v2"
	"github.com/urfave/cli/v3"
	"golang.org/x/term"

	"github.com/ekristen/cryptkey/pkg/commands/derive"
	"github.com/ekristen/cryptkey/pkg/common"
	"github.com/ekristen/cryptkey/pkg/config"
	"github.com/ekristen/cryptkey/pkg/crypto"
	"github.com/ekristen/cryptkey/pkg/enrollment"
	"github.com/ekristen/cryptkey/pkg/progress"
	"github.com/ekristen/cryptkey/pkg/provider"
	"github.com/ekristen/cryptkey/pkg/tui"
)

// Options controls a rekey invocation.
type Options struct {
	// Threshold is the new threshold. Zero means keep the current threshold.
	Threshold int

	// Keep is an explicit list of providers (as "type:id") to retain. If
	// empty, all existing providers are kept (subject to Remove).
	Keep []string

	// Remove is the list of providers (as "type:id") to drop from the new
	// profile.
	Remove []string

	// Add is the list of providers to enroll into the new profile, in the
	// same "type" or "type:id" format that `cryptkey init --add` accepts.
	Add []string

	// NoTUI forces plain-line prompts for the unlock and enroll phases.
	NoTUI bool

	// NoBackup skips writing <profile>.toml.bak before the new profile is
	// saved. The default is to write a backup.
	NoBackup bool

	// Timeout overrides the default hardware provider timeout during the
	// unlock phase. Zero means use the provider's default.
	Timeout time.Duration
}

// isTTY reports whether stderr is connected to a terminal.
func isTTY() bool {
	return term.IsTerminal(int(os.Stderr.Fd())) //nolint:gosec
}

// planFlagsSet reports whether the user supplied any flag that already
// describes the plan, in which case the TUI should be skipped.
//
//nolint:gocritic // opts is read-only; passing by value keeps the call site uncluttered
func planFlagsSet(o Options) bool {
	return o.Threshold > 0 || len(o.Keep) > 0 || len(o.Remove) > 0 || len(o.Add) > 0
}

// rekeyTUIResult is what runRekeyTUI reports back to Execute.
type rekeyTUIResult struct {
	exit tui.RekeyAppExit
	plan tui.RekeyPlan
}

// runRekeyTUI launches the full bubbletea rekey orchestrator and returns
// its exit reason + resolved plan.
func runRekeyTUI(ctx context.Context, profileName string, profile *config.Profile) (rekeyTUIResult, error) {
	m := tui.NewRekeyApp(ctx, profileName, profile)
	p := tea.NewProgram(m, tea.WithOutput(os.Stderr))
	final, err := p.Run()
	if err != nil {
		return rekeyTUIResult{}, fmt.Errorf("rekey tui: %w", err)
	}
	am := final.(tui.RekeyAppModel)
	if appErr := am.Err(); appErr != nil {
		return rekeyTUIResult{}, appErr
	}
	return rekeyTUIResult{exit: am.Exit(), plan: am.Plan()}, nil
}

// Execute is the cli.Command Action for `rekey`.
func Execute(ctx context.Context, cmd *cli.Command) error {
	profileName := cmd.Args().First()
	if profileName == "" {
		profileName = config.DefaultProfile
	}

	opts := Options{
		Threshold: cmd.Int("threshold"),
		Keep:      cmd.StringSlice("keep"),
		Remove:    cmd.StringSlice("remove"),
		Add:       cmd.StringSlice("add"),
		NoTUI:     cmd.Bool("no-tui"),
		NoBackup:  cmd.Bool("no-backup"),
		Timeout:   cmd.Duration("timeout"),
	}

	// If the user didn't supply any plan-shaping flags and we're attached
	// to a TTY, run the full bubbletea rekey app. It owns plan → unlock
	// → fill-in → enroll → write. For profiles containing provider
	// types that don't yet have a TUI unlock component, the app exits
	// with RekeyAppExitFallbackCLI so we continue with the tested CLI
	// flow for the unlock/enroll/write phases.
	if !opts.NoTUI && isTTY() && !planFlagsSet(opts) {
		profile, err := config.Load(profileName)
		if err != nil {
			return err
		}
		appResult, appErr := runRekeyTUI(ctx, profileName, profile)
		if appErr != nil {
			return appErr
		}
		switch appResult.exit {
		case tui.RekeyAppExitSuccess:
			// Everything happened inside the TUI.
			return nil
		case tui.RekeyAppExitCanceled:
			return errors.New("rekey canceled")
		case tui.RekeyAppExitFallbackCLI:
			// Thread the confirmed plan into opts and continue with CLI.
			plan := appResult.plan
			opts.Threshold = plan.Threshold
			opts.Keep = plan.Keep
			opts.Remove = plan.Remove
			opts.Add = plan.Add
		}
	}

	if v := cmd.String("fido2-uv"); v != "" {
		switch v {
		case "discouraged", "preferred", "required":
			ctx = context.WithValue(ctx, provider.CtxFIDO2UV, v)
		default:
			return errors.New("--fido2-uv must be discouraged, preferred, or required")
		}
	}
	if v := cmd.Int("argon-time"); v > 0 {
		ctx = context.WithValue(ctx, provider.CtxArgonTime, uint32(v)) //nolint:gosec
	}
	if v := cmd.Int("argon-memory"); v > 0 {
		ctx = context.WithValue(ctx, provider.CtxArgonMemory, uint32(v)) //nolint:gosec
	}
	if v := cmd.Int("argon-threads"); v > 0 {
		ctx = context.WithValue(ctx, provider.CtxArgonThreads, uint8(v)) //nolint:gosec
	}

	return Run(ctx, profileName, opts)
}

// Run executes a rekey with explicit options. Exposed for tests.
//
//nolint:gocyclo,funlen,gocritic // top-level orchestration with sequential unlock, kept-fill-in, enroll, write phases
func Run(ctx context.Context, profileName string, opts Options) error {
	profile, err := config.Load(profileName)
	if err != nil {
		return err
	}

	keep, removeSet, err := resolveKeptProviders(profile, opts)
	if err != nil {
		return err
	}

	newThreshold := profile.Threshold
	if opts.Threshold > 0 {
		newThreshold = opts.Threshold
	}
	newCount := len(keep) + len(opts.Add)
	if newThreshold < 2 {
		return errors.New("threshold must be at least 2")
	}
	if newCount < newThreshold {
		return fmt.Errorf(
			"new provider count %d is less than threshold %d (keep %d + add %d)",
			newCount, newThreshold, len(keep), len(opts.Add),
		)
	}

	fmt.Fprintf(os.Stderr,
		"Rekeying %q: %d kept, %d added, %d removed → %d providers, threshold %d\n\n",
		profileName, len(keep), len(opts.Add), len(removeSet), newCount, newThreshold,
	)

	// Phase 1: unlock the existing profile via the standard derive flow.
	// This iterates every provider in the current profile (kept or removed),
	// lets the user skip individual ones, and stops as soon as threshold-many
	// shares have been decrypted and the integrity HMAC verifies.
	fmt.Fprintln(os.Stderr, "Step 1/3: unlocking existing profile...")
	res, err := derive.ReconstructMasterKey(ctx, profileName, derive.ReconstructOpts{
		NoTUI:   opts.NoTUI,
		Timeout: opts.Timeout,
	})
	if err != nil {
		return fmt.Errorf("unlock existing profile: %w", err)
	}
	defer res.Wipe()

	// Phase 1b: for every kept provider whose secret we don't already have
	// (because the unlock loop hit threshold before reaching it), derive it
	// now. Without its secret we can't re-encrypt its new share.
	//
	// Install prompt callbacks on a *local* context that only lives for this
	// phase. We deliberately don't overwrite the outer ctx — the subsequent
	// enroll phase should run with the plain ctx so providers don't see
	// both their direct-stderr writes AND a progress callback (which would
	// duplicate every "Touch your key..." line).
	missing := make([]config.ProviderConfig, 0, len(keep))
	for _, pc := range keep {
		if _, ok := res.Secrets[providerKey(pc.Type, pc.ID)]; !ok {
			missing = append(missing, pc)
		}
	}
	if len(missing) > 0 {
		fmt.Fprintf(os.Stderr, "\nCollecting secrets for %d kept provider(s) not used during unlock...\n", len(missing))
		pw := progress.New(os.Stderr, isTTY(), opts.NoTUI, false)
		fillCtx := derive.InstallPromptCallbacks(ctx, pw)
		if err := collectMissingKeptSecrets(fillCtx, missing, res.Secrets, pw, opts.Timeout); err != nil {
			return err
		}
	}

	// Phase 2: enroll any new providers.
	var newEnrollments []enrollment.Enrollment
	if len(opts.Add) > 0 {
		fmt.Fprintln(os.Stderr, "\nStep 2/3: enrolling new providers...")
		enrollPw := progress.New(os.Stderr, isTTY(), opts.NoTUI, false)
		newEnrollments, err = enrollAdded(ctx, opts.Add, keep, enrollPw)
		if err != nil {
			return err
		}
	} else {
		fmt.Fprintln(os.Stderr, "\nStep 2/3: no new providers to enroll.")
	}

	// Phase 3: assemble the full enrollment list (kept first, in profile
	// order, then added) and write the new profile.
	all := make([]enrollment.Enrollment, 0, len(keep)+len(newEnrollments))
	for _, pc := range keep {
		secret, ok := res.Secrets[providerKey(pc.Type, pc.ID)]
		if !ok {
			return fmt.Errorf("internal: missing secret for kept provider %s:%s", pc.Type, pc.ID)
		}
		p, _ := provider.Get(pc.Type)
		// Copy the secret because WriteProfile wipes enrollments' secrets.
		// res.Secrets keeps its own copy that res.Wipe() handles.
		secretCopy := make([]byte, len(secret))
		copy(secretCopy, secret)
		all = append(all, enrollment.Enrollment{
			Provider: p,
			ID:       pc.ID,
			Secret:   secretCopy,
			Params:   pc.Params,
		})
	}
	all = append(all, newEnrollments...)

	outputSalt, err := res.Profile.OutputSaltBytes()
	if err != nil {
		return fmt.Errorf("decode existing output_salt: %w", err)
	}

	fmt.Fprintln(os.Stderr, "\nStep 3/3: writing new profile...")

	if !opts.NoBackup {
		bakPath, _, err := config.Backup(profileName)
		if err != nil {
			return fmt.Errorf("backup existing profile: %w", err)
		}
		fmt.Fprintf(os.Stderr, "Backed up existing profile to %s\n", bakPath)
	}

	if err := enrollment.WriteProfile(profileName, newThreshold, res.MasterKey, outputSalt, all); err != nil {
		return fmt.Errorf("write new profile: %w", err)
	}

	path, _ := config.Path(profileName)
	fmt.Fprintf(os.Stderr, "Profile rewritten to %s\n", path)
	fmt.Fprintf(os.Stderr, "%d providers, threshold %d. Output keys derived from this profile are unchanged.\n",
		newCount, newThreshold)

	return nil
}

// resolveKeptProviders walks the existing profile and returns the providers
// to keep in the new one, plus the set of (type:id) entries explicitly
// removed (used only for the summary line).
//
//nolint:gocritic // opts is read-only; passing by value keeps the call site uncluttered
func resolveKeptProviders(profile *config.Profile, opts Options) (keep []config.ProviderConfig, removed map[string]bool, err error) {
	removed = make(map[string]bool, len(opts.Remove))
	for _, r := range opts.Remove {
		removed[r] = true
	}

	var explicitKeep map[string]bool
	if len(opts.Keep) > 0 {
		explicitKeep = make(map[string]bool, len(opts.Keep))
		for _, k := range opts.Keep {
			explicitKeep[k] = true
		}
	}

	for _, pc := range profile.Providers {
		key := providerKey(pc.Type, pc.ID)
		if removed[key] {
			continue
		}
		if explicitKeep != nil && !explicitKeep[key] {
			continue
		}
		keep = append(keep, pc)
	}

	// Validate that every --keep / --remove name actually exists.
	existing := make(map[string]bool, len(profile.Providers))
	for _, pc := range profile.Providers {
		existing[providerKey(pc.Type, pc.ID)] = true
	}
	for _, k := range opts.Keep {
		if !existing[k] {
			return nil, nil, fmt.Errorf("--keep %q: not a provider in this profile", k)
		}
	}
	for _, r := range opts.Remove {
		if !existing[r] {
			return nil, nil, fmt.Errorf("--remove %q: not a provider in this profile", r)
		}
	}
	return keep, removed, nil
}

// collectMissingKeptSecrets derives the listed providers (those that are being
// kept but whose secrets we don't already have from the unlock phase) and
// writes each secret into secrets, keyed by "type:id". The secret is needed
// so the kept provider's new share can be encrypted against it.
//
// Unlike unlock, there's no threshold here — every listed provider must
// produce a secret. If the user skips one we abort, because we can't write
// a valid share for a kept provider whose secret we don't have. The user
// can either provide it or remove the provider from the new profile.
func collectMissingKeptSecrets(
	ctx context.Context,
	missing []config.ProviderConfig,
	secrets map[string][]byte,
	pw *progress.Writer,
	timeout time.Duration,
) error {
	for _, pc := range missing {
		p, ok := provider.Get(pc.Type)
		if !ok {
			return fmt.Errorf("provider %q not registered (build missing this provider?)", pc.Type)
		}

		secret, skipped := derive.DeriveSingleProvider(ctx, p, &pc, pw, timeout)
		if skipped {
			return fmt.Errorf(
				"kept provider %s:%s was skipped — either derive it, or --remove it from the new profile",
				pc.Type, pc.ID,
			)
		}
		if secret == nil {
			return fmt.Errorf("derive %s:%s failed", pc.Type, pc.ID)
		}

		// Verify the secret actually matches the stored share (catch wrong
		// passphrase for a kept provider early).
		es, derr := pc.EncryptedShareData()
		if derr != nil {
			crypto.WipeBytes(secret)
			return fmt.Errorf("decode share for %s:%s: %w", pc.Type, pc.ID, derr)
		}
		aad := []byte(pc.Type + ":" + pc.ID)
		share, derr := crypto.DecryptShare(secret, aad, es)
		if derr != nil {
			crypto.WipeBytes(secret)
			return fmt.Errorf(
				"verify %s:%s: share decryption failed — wrong secret for kept provider",
				pc.Type, pc.ID,
			)
		}
		crypto.WipeBytes(share) // we only needed it to verify

		secrets[providerKey(pc.Type, pc.ID)] = secret
	}
	return nil
}

// enrollAdded runs Enroll for each --add provider. Each enrollment is
// bracketed by pw.Starting (committed "» type enrolling (id)" line) and
// pw.Emit StatusSucceeded / StatusFailed, so the enroll phase visually
// matches the unlock phase. ids must not collide with existing kept
// providers.
func enrollAdded(
	ctx context.Context,
	addSpecs []string,
	keep []config.ProviderConfig,
	pw *progress.Writer,
) ([]enrollment.Enrollment, error) {
	used := make(map[string]bool, len(keep))
	for _, pc := range keep {
		used[pc.ID] = true
	}

	var out []enrollment.Enrollment
	for _, spec := range addSpecs {
		typeName, id := parseAddSpec(spec)
		p, ok := provider.Get(typeName)
		if !ok {
			return nil, fmt.Errorf("--add %q: unknown provider type", spec)
		}
		if id == "" {
			id = nextDefaultID(typeName, used)
		}
		if used[id] {
			return nil, fmt.Errorf("--add %q: provider id %q already in use in this profile", spec, id)
		}
		used[id] = true

		pw.Starting(typeName, id, "enrolling")
		e, err := enrollment.EnrollProvider(ctx, p, id)
		if err != nil {
			pw.Emit(progress.Event{
				Provider: typeName, ID: id,
				Status:  progress.StatusFailed,
				Message: err.Error(),
			})
			return nil, fmt.Errorf("enroll %q: %w", id, err)
		}
		pw.Emit(progress.Event{Provider: typeName, ID: id, Status: progress.StatusSucceeded})
		out = append(out, *e)
	}
	return out, nil
}

func parseAddSpec(spec string) (typeName, id string) {
	if idx := strings.IndexByte(spec, ':'); idx >= 0 {
		return spec[:idx], spec[idx+1:]
	}
	return spec, ""
}

func nextDefaultID(typeName string, used map[string]bool) string {
	for i := 1; ; i++ {
		candidate := fmt.Sprintf("%s-%d", typeName, i)
		if !used[candidate] {
			return candidate
		}
	}
}

func providerKey(typeName, id string) string { return typeName + ":" + id }

// Confirm returns true if the user (interactively) approves a destructive
// action. Currently unused — kept for a future --interactive confirmation
// step before overwriting a profile.
//
//nolint:unused
func confirm(prompt string) bool {
	if !isTTY() {
		return false
	}
	fmt.Fprint(os.Stderr, prompt)
	r := bufio.NewReader(os.Stdin)
	line, _ := r.ReadString('\n')
	line = strings.TrimSpace(strings.ToLower(line))
	return line == "y" || line == "yes"
}

func init() {
	cmd := &cli.Command{
		Name:      "rekey",
		Usage:     "Re-split the master key across a new provider set, preserving derived output keys",
		ArgsUsage: "[profile]",
		Flags: []cli.Flag{
			&cli.IntFlag{
				Name:    "threshold",
				Aliases: []string{"t"},
				Usage:   "New threshold (default: keep current)",
			},
			&cli.StringSliceFlag{
				Name:  "keep",
				Usage: "Explicit list of providers to keep (type:id, repeatable). Default: keep all.",
			},
			&cli.StringSliceFlag{
				Name:  "remove",
				Usage: "Providers to drop from the new profile (type:id, repeatable)",
			},
			&cli.StringSliceFlag{
				Name:    "add",
				Aliases: []string{"a"},
				Usage:   "Providers to enroll into the new profile (type or type:id, repeatable)",
			},
			&cli.BoolFlag{
				Name:  "no-tui",
				Usage: "Force plain-line prompts (no colors, no inline editing). Implied when stderr is not a terminal.",
			},
			&cli.BoolFlag{
				Name:  "no-backup",
				Usage: "Skip writing <profile>.toml.bak before saving the new profile",
			},
			&cli.DurationFlag{
				Name:  "timeout",
				Usage: "Hardware provider timeout during unlock (default: provider-specific, typically 30s)",
			},
			&cli.StringFlag{
				Name:  "fido2-uv",
				Usage: "FIDO2 user verification for newly enrolled providers (discouraged, preferred, required)",
			},
			&cli.IntFlag{
				Name:  "argon-time",
				Usage: "Argon2id time/iterations for newly enrolled passphrase / recovery providers",
			},
			&cli.IntFlag{
				Name:  "argon-memory",
				Usage: "Argon2id memory in KiB for newly enrolled passphrase / recovery providers",
			},
			&cli.IntFlag{
				Name:  "argon-threads",
				Usage: "Argon2id parallelism for newly enrolled passphrase / recovery providers",
			},
		},
		Action: Execute,
	}
	common.RegisterCommand(cmd)
}
