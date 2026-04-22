package derive

import (
	"context"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/urfave/cli/v3"
)

// TestProfileNameArg_StripsChildArgs verifies that args after "--" (which
// urfave/cli/v3 folds into cmd.Args()) are not mistaken for the profile name.
// Regression: `cryptkey derive --raw -- sudo veracrypt …` previously tried to
// load a profile named "sudo".
func TestProfileNameArg_StripsChildArgs(t *testing.T) {
	tests := []struct {
		name   string
		osArgs []string
		want   string
	}{
		{
			name:   "no profile, no child",
			osArgs: []string{"cryptkey", "derive"},
			want:   "",
		},
		{
			name:   "profile only",
			osArgs: []string{"cryptkey", "derive", "myprofile"},
			want:   "myprofile",
		},
		{
			name:   "default profile with child",
			osArgs: []string{"cryptkey", "derive", "--raw", "--", "sudo", "veracrypt", "-t", "-c"},
			want:   "",
		},
		{
			name:   "explicit profile with child",
			osArgs: []string{"cryptkey", "derive", "myprofile", "--", "echo", "hi"},
			want:   "myprofile",
		},
	}

	origArgs := os.Args
	t.Cleanup(func() { os.Args = origArgs })

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			os.Args = tt.osArgs

			var got string
			cmd := &cli.Command{
				Name: "derive",
				Flags: []cli.Flag{
					&cli.BoolFlag{Name: "raw"},
				},
				Action: func(_ context.Context, c *cli.Command) error {
					got = profileNameArg(c)
					return nil
				},
			}

			err := cmd.Run(context.Background(), tt.osArgs[1:])
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}
