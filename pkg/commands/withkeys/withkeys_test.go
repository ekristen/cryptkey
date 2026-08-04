package withkeys

import (
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ekristen/cryptkey/pkg/config"
)

func TestParseKeySpec(t *testing.T) {
	cases := []struct {
		in      string
		want    keySpec
		wantErr string
	}{
		{in: "vault", want: keySpec{profile: "vault", use: config.DefaultProfile}},
		{in: "vault:disk", want: keySpec{profile: "vault", use: "disk"}},
		{in: "vault:", want: keySpec{profile: "vault", use: config.DefaultProfile}},
		{in: ":disk", want: keySpec{profile: config.DefaultProfile, use: "disk"}},
		{in: "", wantErr: "profile[:use]"},
		{in: "   ", wantErr: "profile[:use]"},
		{in: "vault:a:b", wantErr: "may not contain"},
	}

	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			got, err := parseKeySpec(tc.in)
			if tc.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.wantErr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestSubstitute(t *testing.T) {
	paths := []string{"/dev/fd/3", "/dev/fd/4"}

	t.Run("joined placeholder expands in place", func(t *testing.T) {
		got, err := substitute([]string{"--keyfiles={keys}"}, paths)
		require.NoError(t, err)
		assert.Equal(t, []string{"--keyfiles=/dev/fd/3,/dev/fd/4"}, got)
	})

	t.Run("positional placeholders", func(t *testing.T) {
		got, err := substitute([]string{"{1}", "and", "{2}"}, paths)
		require.NoError(t, err)
		assert.Equal(t, []string{"/dev/fd/3", "and", "/dev/fd/4"}, got)
	})

	t.Run("keyN spelling is equivalent to N", func(t *testing.T) {
		got, err := substitute([]string{"--primary={key1}", "--secondary={key2}"}, paths)
		require.NoError(t, err)
		assert.Equal(t, []string{"--primary=/dev/fd/3", "--secondary=/dev/fd/4"}, got)
	})

	t.Run("both spellings can be mixed", func(t *testing.T) {
		got, err := substitute([]string{"{key1}:{2}"}, paths)
		require.NoError(t, err)
		assert.Equal(t, []string{"/dev/fd/3:/dev/fd/4"}, got)
	})

	t.Run("out of range index is an error", func(t *testing.T) {
		_, err := substitute([]string{"--keyfiles={1},{3}"}, paths)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "{3}")
		assert.Contains(t, err.Error(), "only 2 key(s)")
	})

	t.Run("out of range keyN is an error", func(t *testing.T) {
		_, err := substitute([]string{"--keyfiles={key3}"}, paths)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "{key3}")
		assert.Contains(t, err.Error(), "only 2 key(s)")
	})

	t.Run("argv without placeholders is untouched", func(t *testing.T) {
		got, err := substitute([]string{"veracrypt", "-t"}, paths)
		require.NoError(t, err)
		assert.Equal(t, []string{"veracrypt", "-t"}, got)
	})
}

func TestMaterializeWipesKeys(t *testing.T) {
	keys := [][]byte{[]byte("aaaaaaaaaaaaaaaa"), []byte("bbbbbbbbbbbbbbbb")}
	originals := [][]byte{keys[0], keys[1]}

	readers, err := materialize(keys)
	require.NoError(t, err)
	t.Cleanup(func() {
		for _, r := range readers {
			_ = r.Close()
		}
	})

	for i, orig := range originals {
		assert.Equal(t, make([]byte, len(orig)), orig,
			"key %d must be zeroed once its bytes are in the pipe", i+1)
	}
}

// TestChildReadsDescriptors is the load-bearing test: it proves that a child
// process can read the key material by path at /dev/fd/N, which is the whole
// mechanism the command depends on. If this fails on a platform, the fd
// backend does not work there.
func TestChildReadsDescriptors(t *testing.T) {
	keys := [][]byte{[]byte("key-one-material"), []byte("key-two-material")}

	readers, err := materialize(keys)
	require.NoError(t, err)
	t.Cleanup(func() {
		for _, r := range readers {
			_ = r.Close()
		}
	})

	paths := make([]string, len(readers))
	for i := range readers {
		paths[i] = fdPath(firstChildFD + i)
	}

	argv, err := substitute([]string{"sh", "-c", "cat {1}; echo; cat {2}"}, paths)
	require.NoError(t, err)

	child := exec.CommandContext(t.Context(), argv[0], argv[1:]...) //nolint:gosec // test-controlled argv
	child.ExtraFiles = readers
	child.Stderr = os.Stderr

	out, err := child.Output()
	require.NoError(t, err, "child could not read the inherited descriptors")
	assert.Equal(t, "key-one-material\nkey-two-material", string(out))
}

// TestDescriptorsAreSingleShot documents the backend's central limitation:
// a pipe is consumed by the first reader, so a second read sees EOF. This is
// why the command is scoped to unlocking rather than create-then-mount flows.
func TestDescriptorsAreSingleShot(t *testing.T) {
	readers, err := materialize([][]byte{[]byte("only-once")})
	require.NoError(t, err)
	t.Cleanup(func() { _ = readers[0].Close() })

	argv, err := substitute([]string{"sh", "-c", "cat {1}; echo -n '|'; cat {1}"},
		[]string{fdPath(firstChildFD)})
	require.NoError(t, err)

	child := exec.CommandContext(t.Context(), argv[0], argv[1:]...) //nolint:gosec // test-controlled argv
	child.ExtraFiles = readers
	child.Stderr = os.Stderr

	out, err := child.Output()
	require.NoError(t, err)
	assert.Equal(t, "only-once|", string(out),
		"the second read must return nothing")
}

func TestFindChildArgs(t *testing.T) {
	saved := os.Args
	t.Cleanup(func() { os.Args = saved })

	os.Args = []string{"cryptkey", "with-keys", "--key", "vault", "--", "veracrypt", "-t"}
	assert.Equal(t, []string{"veracrypt", "-t"}, findChildArgs())

	os.Args = []string{"cryptkey", "with-keys", "--key", "vault"}
	assert.Nil(t, findChildArgs())

	os.Args = []string{"cryptkey", "with-keys", "--key", "vault", "--"}
	assert.Nil(t, findChildArgs(), "a trailing -- with no command is not a command")
}

func TestSubstituteOrderMatchesKeyOrder(t *testing.T) {
	paths := []string{fdPath(3), fdPath(4), fdPath(5)}
	got, err := substitute([]string{"--keyfiles={keys}"}, paths)
	require.NoError(t, err)
	assert.Equal(t, "--keyfiles=/dev/fd/3,/dev/fd/4,/dev/fd/5", got[0])
	assert.True(t, strings.HasPrefix(got[0], "--keyfiles=/dev/fd/3"))
}
