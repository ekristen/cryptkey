module github.com/ekristen/cryptkey

go 1.25.1

require (
	charm.land/bubbles/v2 v2.1.0
	charm.land/bubbletea/v2 v2.0.6
	charm.land/lipgloss/v2 v2.0.3
	github.com/BurntSushi/toml v1.6.0
	github.com/go-piv/piv-go/v2 v2.6.0
	github.com/google/go-tpm v0.9.8
	github.com/keys-pub/go-libfido2 v1.5.3
	github.com/nbutton23/zxcvbn-go v0.0.0-20210217022336-fa2cb2858354
	github.com/rancher/wrangler v1.1.2
	github.com/sirupsen/logrus v1.9.4
	github.com/stretchr/testify v1.11.1
	github.com/urfave/cli/v3 v3.8.0
	golang.org/x/crypto v0.50.0
	golang.org/x/sys v0.43.0
	golang.org/x/term v0.42.0
)

require (
	github.com/atotto/clipboard v0.1.4 // indirect
	github.com/charmbracelet/colorprofile v0.4.3 // indirect
	github.com/charmbracelet/ultraviolet v0.0.0-20260420095748-421e4a7fa8d7 // indirect
	github.com/charmbracelet/x/ansi v0.11.7 // indirect
	github.com/charmbracelet/x/term v0.2.2 // indirect
	github.com/charmbracelet/x/termios v0.1.1 // indirect
	github.com/charmbracelet/x/windows v0.2.2 // indirect
	github.com/clipperhouse/displaywidth v0.11.0 // indirect
	github.com/clipperhouse/uax29/v2 v2.7.0 // indirect
	github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc // indirect
	github.com/kr/pretty v0.3.1 // indirect
	github.com/lucasb-eyer/go-colorful v1.4.0 // indirect
	github.com/mattn/go-runewidth v0.0.23 // indirect
	github.com/muesli/cancelreader v0.2.2 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/pmezard/go-difflib v1.0.1-0.20181226105442-5d4384ee4fb2 // indirect
	github.com/rivo/uniseg v0.4.7 // indirect
	github.com/rogpeppe/go-internal v1.14.1 // indirect
	github.com/xo/terminfo v0.0.0-20220910002029-abceb7e1c41e // indirect
	golang.org/x/sync v0.20.0 // indirect
	gopkg.in/check.v1 v1.0.0-20201130134442-10cb98267c6c // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

replace github.com/keys-pub/go-libfido2 => github.com/ekristen/go-libfido2 v0.0.0-20260417204846-0403d3f496cd
