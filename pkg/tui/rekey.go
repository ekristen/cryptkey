package tui

import (
	"fmt"
	"strconv"
	"strings"

	tea "charm.land/bubbletea/v2"

	"github.com/ekristen/cryptkey/pkg/config"
	"github.com/ekristen/cryptkey/pkg/provider"
)

// RekeyPlan is the planning result returned by the rekey TUI.
type RekeyPlan struct {
	Threshold int      // new threshold; always populated
	Keep      []string // providers (type:id) explicitly kept
	Remove    []string // providers (type:id) the user toggled off
	Add       []string // provider type names to enroll fresh
}

// rekeyState identifies the active screen inside the rekey TUI.
type rekeyState int

const (
	rekeyStateReview   rekeyState = iota // main planning screen
	rekeyStateAddType                    // pick a provider type to add
	rekeyStateDone                       // user pressed enter — exit and run
	rekeyStateCanceled                   // user pressed ctrl+c / esc out of review
)

// rekeyEntry tracks one provider in the planning UI: either an existing one
// (with a kept toggle) or a queued add.
type rekeyEntry struct {
	key     string // "type:id" for existing; "+type" for queued add
	kept    bool   // existing only — false means user removed it
	isAdd   bool
	addType string // populated when isAdd
}

// RekeyModel is the bubbletea model for the planning step of `cryptkey rekey`.
//
// The model is intentionally limited to the *planning* phase: review the
// existing provider set, toggle keep/remove, choose a new threshold, and
// queue type-only adds. After the user confirms, the rekey command exits
// the TUI and runs the actual unlock + enroll + write phases through the
// regular terminal so the polished masked-prompt UX from `derive` carries
// over without being re-implemented inside bubbletea.
type RekeyModel struct {
	profileName string
	profile     *config.Profile

	entries   []rekeyEntry
	cursor    int // index into entries; len(entries) selects the threshold row
	threshold int

	state rekeyState

	// add-picker state
	providers []provider.Provider
	addCursor int

	err string
}

// NewRekey builds a rekey TUI model seeded from an existing profile.
func NewRekey(profileName string, p *config.Profile) RekeyModel {
	entries := make([]rekeyEntry, 0, len(p.Providers))
	for _, pc := range p.Providers {
		entries = append(entries, rekeyEntry{
			key:  pc.Type + ":" + pc.ID,
			kept: true,
		})
	}
	return RekeyModel{
		profileName: profileName,
		profile:     p,
		entries:     entries,
		threshold:   p.Threshold,
		state:       rekeyStateReview,
		providers:   provider.All(),
	}
}

// Init satisfies the tea.Model interface.
func (m RekeyModel) Init() tea.Cmd { return nil }

// Update routes key messages based on the active sub-screen.
func (m RekeyModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	km, ok := msg.(tea.KeyMsg)
	if !ok {
		return m, nil
	}
	if km.String() == "ctrl+c" {
		m.state = rekeyStateCanceled
		return m, tea.Quit
	}

	switch m.state {
	case rekeyStateReview:
		return m.handleReview(km.String())
	case rekeyStateAddType:
		return m.handleAddType(km.String())
	}
	return m, nil
}

// totalRows is the number of focusable rows on the review screen:
// every entry, plus one row for the threshold control.
func (m RekeyModel) totalRows() int { return len(m.entries) + 1 }

// rowIsThreshold returns true when the cursor sits on the threshold row.
func (m RekeyModel) rowIsThreshold() bool { return m.cursor == len(m.entries) }

//nolint:gocyclo // key-dispatch switch
func (m RekeyModel) handleReview(key string) (tea.Model, tea.Cmd) {
	switch key {
	case keyUp, "k":
		if m.cursor > 0 {
			m.cursor--
		}
	case keyDown, "j":
		if m.cursor < m.totalRows()-1 {
			m.cursor++
		}
	case " ", keySpace, "x":
		// Toggle kept on entries (no-op on add rows or threshold row)
		if !m.rowIsThreshold() {
			e := &m.entries[m.cursor]
			if e.isAdd {
				// Pressing space on a queued add removes it
				m.entries = append(m.entries[:m.cursor], m.entries[m.cursor+1:]...)
				if m.cursor >= len(m.entries) && m.cursor > 0 {
					m.cursor--
				}
			} else {
				e.kept = !e.kept
			}
		}
	case "a":
		m.state = rekeyStateAddType
		m.addCursor = 0
		m.err = ""
	case keyLeft:
		if m.rowIsThreshold() && m.threshold > 2 {
			m.threshold--
		}
	case keyRight:
		if m.rowIsThreshold() {
			limit := m.providerCount()
			if m.threshold < limit {
				m.threshold++
			}
		}
	case keyEnter:
		if !m.validatePlan() {
			return m, nil
		}
		m.state = rekeyStateDone
		return m, tea.Quit
	case keyEscape:
		m.state = rekeyStateCanceled
		return m, tea.Quit
	}
	return m, nil
}

func (m RekeyModel) handleAddType(key string) (tea.Model, tea.Cmd) {
	switch key {
	case keyUp, "k":
		if m.addCursor > 0 {
			m.addCursor--
		}
	case keyDown, "j":
		if m.addCursor < len(m.providers)-1 {
			m.addCursor++
		}
	case keyEnter:
		t := m.providers[m.addCursor].Type()
		m.entries = append(m.entries, rekeyEntry{
			key:     "+" + t,
			isAdd:   true,
			addType: t,
		})
		m.cursor = len(m.entries) - 1
		m.state = rekeyStateReview
	case keyEscape:
		m.state = rekeyStateReview
	}
	return m, nil
}

// providerCount returns the number of providers in the resulting profile
// (kept + queued adds).
func (m RekeyModel) providerCount() int {
	n := 0
	for _, e := range m.entries {
		if e.isAdd {
			n++
		} else if e.kept {
			n++
		}
	}
	return n
}

func (m *RekeyModel) validatePlan() bool {
	count := m.providerCount()
	if m.threshold < 2 {
		m.err = "threshold must be at least 2"
		return false
	}
	if count < m.threshold {
		m.err = fmt.Sprintf("threshold %d > %d providers — add more, lower threshold, or restore a removed provider", m.threshold, count)
		return false
	}
	return true
}

// View renders the active screen.
func (m RekeyModel) View() tea.View {
	if m.state == rekeyStateDone || m.state == rekeyStateCanceled {
		v := tea.NewView("")
		v.AltScreen = true
		return v
	}

	var b strings.Builder
	b.WriteString(titleStyle.Render("cryptkey rekey"))
	b.WriteString("  ")
	b.WriteString(subtitleStyle.Render(m.profileName))
	b.WriteString("\n\n")

	switch m.state {
	case rekeyStateReview:
		m.renderReview(&b)
	case rekeyStateAddType:
		m.renderAddType(&b)
	}

	v := tea.NewView(b.String())
	v.AltScreen = true
	return v
}

func (m RekeyModel) renderReview(b *strings.Builder) {
	b.WriteString(dimStyle.Render(fmt.Sprintf("Current: %d providers, threshold %d",
		len(m.profile.Providers), m.profile.Threshold)))
	b.WriteString("\n\n")

	for i, e := range m.entries {
		cursor := indentTwo
		if i == m.cursor {
			cursor = highlightStyle.Render("> ")
		}
		b.WriteString(cursor)

		switch {
		case e.isAdd:
			b.WriteString(successStyle.Render("[+] "))
			fmt.Fprintf(b, "%s ", highlightStyle.Render(e.addType))
			b.WriteString(dimStyle.Render("(new — id assigned at enroll)"))
		case e.kept:
			b.WriteString(successStyle.Render("[✓] "))
			b.WriteString(e.key)
		default:
			b.WriteString(errorStyle.Render("[✗] "))
			b.WriteString(dimStyle.Render(e.key + "  removed"))
		}
		b.WriteString("\n")
	}

	// Threshold row
	thrCursor := indentTwo
	thrLabel := "Threshold:"
	if m.rowIsThreshold() {
		thrCursor = highlightStyle.Render("> ")
		thrLabel = highlightStyle.Render("Threshold:")
	}
	fmt.Fprintf(b, "\n%s%s %s",
		thrCursor, thrLabel,
		highlightStyle.Render(strconv.Itoa(m.threshold)))
	if m.rowIsThreshold() {
		b.WriteString("  ")
		b.WriteString(dimStyle.Render("←/→ adjust"))
	}
	b.WriteString("\n")

	// Summary
	b.WriteString("\n")
	count := m.providerCount()
	fmt.Fprintf(b, "After rekey: %s providers, threshold %s\n",
		highlightStyle.Render(strconv.Itoa(count)),
		highlightStyle.Render(strconv.Itoa(m.threshold)))

	if m.err != "" {
		b.WriteString("\n")
		b.WriteString(errorStyle.Render(m.err))
		b.WriteString("\n")
	}

	b.WriteString("\n")
	b.WriteString(dimStyle.Render("↑/↓ navigate • space toggle keep/remove • a add provider • enter continue • esc cancel"))
}

func (m RekeyModel) renderAddType(b *strings.Builder) {
	b.WriteString("Add a provider:\n\n")
	for i, p := range m.providers {
		cursor := indentTwo
		if i == m.addCursor {
			cursor = highlightStyle.Render("> ")
		}
		fmt.Fprintf(b, "%s%s", cursor, p.Type())
		fmt.Fprintf(b, "%s\n", dimStyle.Render(" — "+p.Description()))
	}
	b.WriteString("\n")
	b.WriteString(dimStyle.Render("↑/↓ navigate • enter add • esc back"))
}

// Plan returns the resolved rekey plan after Update has reached the done
// state. Calling Plan in any other state returns a zero value.
func (m RekeyModel) Plan() RekeyPlan {
	if m.state != rekeyStateDone {
		return RekeyPlan{}
	}

	plan := RekeyPlan{Threshold: m.threshold}

	// We always set Keep so the rekey command knows the explicit set the
	// user reviewed. Remove is also populated for clarity in the summary
	// line; the rekey command mainly uses Keep + Add to compute the new
	// provider list.
	for _, e := range m.entries {
		if e.isAdd {
			plan.Add = append(plan.Add, e.addType)
			continue
		}
		if e.kept {
			plan.Keep = append(plan.Keep, e.key)
		} else {
			plan.Remove = append(plan.Remove, e.key)
		}
	}
	return plan
}

// Canceled reports true if the user dismissed the TUI without confirming.
func (m RekeyModel) Canceled() bool { return m.state == rekeyStateCanceled }

// Make sure tea.Model is satisfied at compile time.
var _ tea.Model = RekeyModel{}
