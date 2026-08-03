// Package withkeys implements the `cryptkey with-keys` command, which
// materializes one or more derived keys as inherited file descriptors and
// execs a child command that reads them by path (/dev/fd/N).
//
// It exists for consumers that need several keys at once and can only accept
// them as file paths — VeraCrypt's --keyfiles being the motivating case, since
// stdin can only ever be one keyfile.
//
// The key material never touches a filesystem. Each key is written into an
// anonymous pipe whose read end is handed to the child as a numbered file
// descriptor; the bytes live in the kernel pipe buffer and nowhere else.
// Cleanup is therefore structural rather than best-effort: the write ends are
// closed immediately, and the read ends die with the child process. There is
// nothing to unlink, so even a SIGKILL of cryptkey leaves no residue.
//
// Note that a pipe is a single-shot stream: each descriptor can be read once,
// to EOF. That is sufficient for unlocking an existing volume. Operations that
// read the same keyfile twice (VeraCrypt's create-then-mount flow) are not
// covered by this backend.
package withkeys

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"

	"github.com/urfave/cli/v3"

	"github.com/ekristen/cryptkey/pkg/commands/derive"
	"github.com/ekristen/cryptkey/pkg/common"
	"github.com/ekristen/cryptkey/pkg/config"
	"github.com/ekristen/cryptkey/pkg/crypto"
)

// firstChildFD is the descriptor number the first key lands on in the child.
// Go's os/exec contract is that ExtraFiles[i] becomes file descriptor 3+i,
// so the numbering is assigned rather than discovered.
const firstChildFD = 3

// indexPlaceholder matches a positional {N} placeholder in the child argv.
var indexPlaceholder = regexp.MustCompile(`\{(\d+)\}`)

// keySpec is one --key argument: the profile to unlock and the --use label to
// derive under.
type keySpec struct {
	profile string
	use     string
}

func (k keySpec) String() string { return k.profile + ":" + k.use }

// parseKeySpec parses "profile", "profile:use", or ":use" (default profile).
func parseKeySpec(s string) (keySpec, error) {
	if strings.TrimSpace(s) == "" {
		return keySpec{}, errors.New("--key requires a value of the form profile[:use]")
	}
	profile, use, hasUse := strings.Cut(s, ":")
	if profile == "" {
		profile = config.DefaultProfile
	}
	if !hasUse || use == "" {
		use = config.DefaultProfile
	}
	if strings.Contains(use, ":") {
		return keySpec{}, fmt.Errorf("--key %q: use label may not contain ':'", s)
	}
	return keySpec{profile: profile, use: use}, nil
}

// wipeAll zeroes every key in the slice. Safe on nil entries.
func wipeAll(keys [][]byte) {
	for _, k := range keys {
		crypto.WipeBytes(k)
	}
}

// deriveKeys unlocks each distinct profile exactly once and derives one output
// key per spec. The returned slice is parallel to specs; the caller owns every
// element and must wipe it.
//
// Profiles are unlocked sequentially, in the order first named on the command
// line, so provider prompts never overlap and never contend for /dev/tty.
// Several specs naming the same profile with different --use labels share a
// single unlock.
func deriveKeys(ctx context.Context, specs []keySpec, opts *derive.ReconstructOpts) ([][]byte, error) {
	keys := make([][]byte, len(specs))

	var order []string
	byProfile := make(map[string][]int, len(specs))
	for i, s := range specs {
		if _, seen := byProfile[s.profile]; !seen {
			order = append(order, s.profile)
		}
		byProfile[s.profile] = append(byProfile[s.profile], i)
	}

	for _, name := range order {
		res, err := derive.ReconstructMasterKey(ctx, name, *opts)
		if err != nil {
			wipeAll(keys)
			return nil, fmt.Errorf("profile %q: %w", name, err)
		}
		for _, i := range byProfile[name] {
			key, kerr := derive.OutputKeyFor(res, specs[i].use)
			if kerr != nil {
				res.Wipe()
				wipeAll(keys)
				return nil, fmt.Errorf("key %q: %w", specs[i], kerr)
			}
			keys[i] = key
		}
		res.Wipe()
	}

	return keys, nil
}

// materialize writes each key into its own anonymous pipe and returns the read
// ends, to be passed as the child's ExtraFiles.
//
// materialize takes ownership of the key slices and wipes each one as soon as
// its bytes are in the kernel pipe buffer — callers must not use them
// afterwards. On any error every pipe opened so far is closed before
// returning, so no descriptor leaks on the failure path.
func materialize(keys [][]byte) ([]*os.File, error) {
	readers := make([]*os.File, 0, len(keys))

	fail := func(format string, args ...any) ([]*os.File, error) {
		for _, r := range readers {
			_ = r.Close()
		}
		wipeAll(keys)
		return nil, fmt.Errorf(format, args...)
	}

	for i, key := range keys {
		r, w, err := os.Pipe()
		if err != nil {
			return fail("key %d: create pipe: %w", i+1, err)
		}
		readers = append(readers, r)

		// A 32-byte key is far below the smallest pipe buffer on any
		// platform we support, so this cannot block despite no reader
		// existing yet — the bytes simply sit in the buffer until the
		// child opens its descriptor.
		_, werr := w.Write(key)
		crypto.WipeBytes(key)

		// Close the write end unconditionally: the child needs EOF to
		// know the keyfile has ended, and leaving it open would hang a
		// reader that reads to EOF.
		cerr := w.Close()

		if werr != nil {
			return fail("key %d: write to pipe: %w", i+1, werr)
		}
		if cerr != nil {
			return fail("key %d: close pipe: %w", i+1, cerr)
		}
	}

	return readers, nil
}

// fdPath returns the path through which the child reads descriptor n. Both
// Linux and macOS expose /dev/fd; on Linux it is a symlink to /proc/self/fd.
func fdPath(n int) string {
	return "/dev/fd/" + strconv.Itoa(n)
}

// substitute expands {keys} (all paths, comma-joined, in --key order) and
// {1}..{N} (individual paths) within each element of the child argv.
func substitute(argv, paths []string) ([]string, error) {
	joined := strings.Join(paths, ",")
	out := make([]string, len(argv))

	for i, arg := range argv {
		expanded := strings.ReplaceAll(arg, "{keys}", joined)
		for j, p := range paths {
			expanded = strings.ReplaceAll(expanded, "{"+strconv.Itoa(j+1)+"}", p)
		}
		// Any {N} still present names a key that wasn't provided. Failing
		// here beats handing the child a literal "{3}" and watching it
		// report a confusing keyfile error.
		if m := indexPlaceholder.FindStringSubmatch(expanded); m != nil {
			return nil, fmt.Errorf(
				"placeholder %s in argument %q: only %d key(s) were provided",
				m[0], arg, len(paths))
		}
		out[i] = expanded
	}

	return out, nil
}

// findChildArgs returns the arguments after "--" in os.Args, if any.
func findChildArgs() []string {
	for i, arg := range os.Args {
		if arg == "--" && i+1 < len(os.Args) {
			return os.Args[i+1:]
		}
	}
	return nil
}

// runChild executes the child, converting an ExitError into a cli.Exit that
// carries the child's own exit code.
func runChild(child *exec.Cmd) error {
	if err := child.Run(); err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return cli.Exit("", exitErr.ExitCode())
		}
		return fmt.Errorf("exec %q: %w", child.Path, err)
	}
	return nil
}

func Execute(ctx context.Context, cmd *cli.Command) error {
	rawKeys := cmd.StringSlice("key")
	if len(rawKeys) == 0 {
		return errors.New("at least one --key profile[:use] is required")
	}

	specs := make([]keySpec, 0, len(rawKeys))
	for _, raw := range rawKeys {
		spec, err := parseKeySpec(raw)
		if err != nil {
			return err
		}
		specs = append(specs, spec)
	}

	childArgs := findChildArgs()
	if len(childArgs) == 0 {
		return errors.New(
			"with-keys requires a command after -- (the descriptors only exist for the child process)")
	}

	keys, err := deriveKeys(ctx, specs, &derive.ReconstructOpts{
		ProviderFilter: cmd.StringSlice("provider"),
		SkipFilter:     cmd.StringSlice("skip"),
		Quiet:          cmd.Bool("quiet"),
		Timeout:        cmd.Duration("timeout"),
		NoTUI:          cmd.Bool("no-tui"),
	})
	if err != nil {
		return err
	}

	// materialize owns keys from here and wipes each one after writing it.
	readers, err := materialize(keys)
	if err != nil {
		return err
	}
	// The child gets its own duplicate of each descriptor at exec time, so
	// closing our copies here is enough; the child's copies are reclaimed by
	// the kernel when it exits, however it exits.
	defer func() {
		for _, r := range readers {
			_ = r.Close()
		}
	}()

	paths := make([]string, len(readers))
	for i := range readers {
		paths[i] = fdPath(firstChildFD + i)
	}

	argv, err := substitute(childArgs, paths)
	if err != nil {
		return err
	}

	child := exec.CommandContext(ctx, argv[0], argv[1:]...) //nolint:gosec // intentional: CLI execs a user-specified command
	child.Stdin = os.Stdin
	child.Stdout = os.Stdout
	child.Stderr = os.Stderr
	child.ExtraFiles = readers

	return runChild(child)
}

func init() {
	cmd := &cli.Command{
		Name:  "with-keys",
		Usage: "Expose derived keys as file descriptors and exec a command that reads them by path",
		Description: "Materializes one derived key per --key as an inherited file descriptor " +
			"(/dev/fd/3, /dev/fd/4, ...) and runs the command after --, substituting {keys} " +
			"for the comma-joined paths and {1}..{N} for individual ones.\n\n" +
			"The keys exist only in kernel pipe buffers for the lifetime of the child " +
			"process; nothing is written to any filesystem and no cleanup step can be " +
			"missed. Each descriptor is readable exactly once, to EOF.\n\n" +
			"Example:\n" +
			"  cryptkey with-keys --key vault:disk --key backup:disk -- \\\n" +
			"    veracrypt -t --keyfiles={keys} --password=\"\" --pim=0 \\\n" +
			"    --non-interactive /path/to/volume /mnt/vault",
		ArgsUsage: "-- <command> [args...]",
		Flags: []cli.Flag{
			&cli.StringSliceFlag{
				Name:  "key",
				Usage: "Key to materialize, as profile[:use] (repeatable, order defines fd order)",
			},
			&cli.StringSliceFlag{
				Name:  "provider",
				Usage: "Only attempt these providers (type:id or type, repeatable)",
			},
			&cli.StringSliceFlag{
				Name:  "skip",
				Usage: "Skip these providers (type:id or type, repeatable)",
			},
			&cli.BoolFlag{
				Name:    "quiet",
				Aliases: []string{"q"},
				Usage:   "Suppress all stderr output except fatal errors",
			},
			&cli.DurationFlag{
				Name:  "timeout",
				Usage: "Hardware provider timeout (default: provider-specific, typically 30s)",
			},
			&cli.BoolFlag{
				Name:  "no-tui",
				Usage: "Force plain-line prompts and output (no colors, no inline editing).",
			},
		},
		Action: Execute,
	}
	common.RegisterCommand(cmd)
}
