package tui

import (
	"charm.land/lipgloss/v2"
)

// Key name constants used across TUI handlers.
const (
	keyUp        = "up"
	keyDown      = "down"
	keyLeft      = "left"
	keyRight     = "right"
	keyEnter     = "enter"
	keyEscape    = "esc"
	keyBackspace = "backspace"
	keySpace     = "space"
)

// Repeated string constants.
const (
	uvPreferred   = "preferred"
	uvDiscouraged = "discouraged"
	uvRequired    = "required"
	indentTwo     = "  "
	typeFIDO2     = "fido2"
	typeRecovery  = "recovery"
)

var (
	titleStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#FFFFFF"))

	subtitleStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#888888"))

	successStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#00FF00"))

	errorStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#FF0000"))

	highlightStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#7DC4E4"))

	dimStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#555555"))

	promptStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#CBA6F7"))

	warningStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#FF8800"))

	codeStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#00FFAA"))
)
