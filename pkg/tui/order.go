package tui

import (
	"fmt"
	"sort"
	"strings"

	tea "charm.land/bubbletea/v2"

	"github.com/ekristen/cryptkey/pkg/enrollment"
)

// providerPriority returns the default sort order for provider types.
// Lower numbers are tried first during derive.
func providerPriority(typeName string) int {
	switch typeName {
	case "tpm":
		return 0 // passive, no interaction, hardware-bound
	case "ssh-agent":
		return 1 // passive, no interaction
	case typeFIDO2:
		return 2 // hardware touch
	case "passkey":
		return 3 // browser interaction
	case "sshkey":
		return 4 // may need passphrase
	case typePassphrase:
		return 5 // always needs input
	case typeRecovery:
		return 6 // last resort, always last
	default:
		return 5
	}
}

// isRecovery returns true if the enrollment is a recovery provider.
func isRecovery(e enrollment.Enrollment) bool {
	return e.Provider.Type() == typeRecovery
}

// movableCount returns the number of non-recovery enrollments (the ones the user can reorder).
func movableCount(enrollments []enrollment.Enrollment) int {
	count := 0
	for _, e := range enrollments {
		if !isRecovery(e) {
			count++
		}
	}
	return count
}

// sortEnrollmentsByPriority sorts enrollments by default priority.
// Recovery providers are always sorted to the end.
func sortEnrollmentsByPriority(enrollments []enrollment.Enrollment) {
	sort.SliceStable(enrollments, func(i, j int) bool {
		return providerPriority(enrollments[i].Provider.Type()) <
			providerPriority(enrollments[j].Provider.Type())
	})
}

func (m Model) handleProviderOrder(key string) (tea.Model, tea.Cmd) {
	movable := movableCount(m.enrollments)

	switch key {
	case keyUp, "k":
		if m.orderCursor > 0 {
			m.orderCursor--
		}
	case keyDown, "j":
		if m.orderCursor < movable-1 {
			m.orderCursor++
		}

	// Move selected provider up in the list
	case "shift+up", "K":
		if m.orderCursor > 0 {
			m.enrollments[m.orderCursor], m.enrollments[m.orderCursor-1] =
				m.enrollments[m.orderCursor-1], m.enrollments[m.orderCursor]
			m.orderCursor--
		}

	// Move selected provider down in the list
	case "shift+down", "J":
		if m.orderCursor < movable-1 {
			m.enrollments[m.orderCursor], m.enrollments[m.orderCursor+1] =
				m.enrollments[m.orderCursor+1], m.enrollments[m.orderCursor]
			m.orderCursor++
		}

	case keyEnter:
		return m.finalize()

	case keyEscape:
		m.state = stateProviderSelect
	}

	return m, nil
}

func (m Model) viewProviderOrder(b *strings.Builder) {
	b.WriteString("Arrange provider order for key derivation:\n")
	b.WriteString(dimStyle.Render("Providers are tried in this order during derive."))
	b.WriteString("\n\n")

	movable := movableCount(m.enrollments)

	for i, e := range m.enrollments {
		if isRecovery(e) {
			// Recovery providers shown at the bottom, not selectable
			b.WriteString(dimStyle.Render(fmt.Sprintf("  %d. %s (%s) — always last",
				i+1, e.ID, e.Provider.Type())))
			b.WriteString("\n")
			continue
		}

		cursor := indentTwo
		style := dimStyle
		if i == m.orderCursor {
			cursor = highlightStyle.Render("> ")
			style = highlightStyle
		}

		fmt.Fprintf(b, "%s%s\n",
			cursor,
			style.Render(fmt.Sprintf("%d. %s (%s)", i+1, e.ID, enrolledDetail(e))))
	}

	if w := enrollment.RecoveryWarning(m.threshold, m.enrollments); w != "" {
		b.WriteString("\n")
		b.WriteString(warningStyle.Render(w))
		b.WriteString("\n")
	}

	if w := enrollment.NonInteractiveWarning(m.threshold, m.enrollments); w != "" {
		b.WriteString("\n")
		b.WriteString(warningStyle.Render(w))
		b.WriteString("\n")
	}

	b.WriteString("\n")
	if movable > 1 {
		b.WriteString(dimStyle.Render("↑/↓ select • shift+↑/↓ or J/K move • enter confirm • escape back"))
	} else {
		b.WriteString(dimStyle.Render("enter confirm • escape back"))
	}
}
