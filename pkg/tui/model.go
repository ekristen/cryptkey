package tui

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"charm.land/bubbles/v2/textinput"
	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"

	"github.com/ekristen/cryptkey/pkg/config"
	"github.com/ekristen/cryptkey/pkg/enrollment"
	"github.com/ekristen/cryptkey/pkg/provider"
)

// state tracks which screen the TUI is on.
type state int

const (
	stateProviderSelect state = iota
	stateProviderSetup        // combined name + options screen

	// Passphrase provider (driven by an enrollPassphrase sub-model)
	stateEnrollPassphrase

	// FIDO2 provider (driven by an enrollFIDO2 sub-model)
	stateEnrollFIDO2

	// SSH Agent provider (driven by an enrollSSHAgent sub-model)
	stateEnrollSSHAgent

	// SSH Key provider (driven by an enrollSSHKey sub-model)
	stateEnrollSSHKey

	// PIV provider (driven by an enrollPIV sub-model)
	stateEnrollPIV

	// Provider ordering (before finalize)
	stateProviderOrder

	// General states
	stateEnrolling
	stateEnrollComplete // shows enrollment result message, waits for enter
	stateDone
	stateError
)

// enrollMsg is sent when a provider enrollment completes.
type enrollMsg struct {
	enrollment *enrollment.Enrollment
	err        error
}

// Model is the top-level bubbletea model for the init TUI.
type Model struct {
	profileName string
	threshold   int
	ctx         context.Context

	state       state
	providers   []provider.Provider
	cursor      int
	enrollments []enrollment.Enrollment
	idInput     string

	selectedProvider provider.Provider
	selectedID       string
	configOptions    []provider.EnrollOption // options for current provider (may be nil)
	configValues     map[string]string       // current values keyed by option Key
	configFocus      int                     // 0 = name field, 1+ = option index
	editingName      bool                    // true when name field is in edit mode

	// Provider ordering fields
	orderCursor int

	passInput   textinput.Model
	statusMsg   string
	errorMsg    string
	progressLog []string // ordered, deduped progress messages for the current enrollment
	quitting    bool

	// Active sub-model for per-provider enroll flows. At most one set at a
	// time; the active one is driven by the corresponding state value.
	passphraseChild *enrollPassphrase
	fido2Child      *enrollFIDO2
	sshAgentChild   *enrollSSHAgent
	sshKeyChild     *enrollSSHKey
	pivChild        *enrollPIV
}

// New creates a new TUI model for profile initialization.
func New(ctx context.Context, profileName string, threshold int) Model {
	ti := textinput.New()
	ti.EchoMode = textinput.EchoPassword
	ti.EchoCharacter = '•'
	ti.Placeholder = ""
	ti.CharLimit = 256

	return Model{
		profileName: profileName,
		threshold:   threshold,
		ctx:         ctx,
		state:       stateProviderSelect,
		providers:   provider.All(),
		passInput:   ti,
	}
}

func (m Model) Init() tea.Cmd {
	return nil
}

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	// Intercept ctrl+c at the top so sub-models can't accidentally swallow it.
	if km, ok := msg.(tea.KeyMsg); ok && km.String() == "ctrl+c" {
		m.quitting = true
		return m, tea.Quit
	}

	// If a sub-model owns the current screen, route to it first.
	if m.state == stateEnrollPassphrase && m.passphraseChild != nil {
		return m.updatePassphraseChild(msg)
	}
	if m.state == stateEnrollFIDO2 && m.fido2Child != nil {
		return m.updateFIDO2Child(msg)
	}
	if m.state == stateEnrollSSHAgent && m.sshAgentChild != nil {
		return m.updateSSHAgentChild(msg)
	}
	if m.state == stateEnrollSSHKey && m.sshKeyChild != nil {
		return m.updateSSHKeyChild(msg)
	}
	if m.state == stateEnrollPIV && m.pivChild != nil {
		return m.updatePIVChild(msg)
	}

	switch msg := msg.(type) {
	case tea.KeyMsg:
		return m.handleKey(msg)
	case enrollMsg:
		return m.handleEnrollResult(msg)
	}

	return m, nil
}

// updatePassphraseChild forwards a message to the passphrase enroll sub-model
// and handles its completion. On success, the result is folded into m via
// handleEnrollResult (same post-enrollment path as every other provider).
// On user cancel, we return to the provider-select screen.
func (m Model) updatePassphraseChild(msg tea.Msg) (tea.Model, tea.Cmd) {
	child, cmd := m.passphraseChild.Update(msg)
	m.passphraseChild = &child

	if !m.passphraseChild.Done() {
		return m, cmd
	}

	if m.passphraseChild.Canceled() {
		m.passphraseChild = nil
		m.state = stateProviderSelect
		m.errorMsg = ""
		return m, cmd
	}

	result, err := m.passphraseChild.Result()
	m.passphraseChild = nil
	return m.handleEnrollResult(enrollMsg{enrollment: result, err: err})
}

// updatePIVChild mirrors updatePassphraseChild for the PIV sub-model.
//
//nolint:dupl // structurally identical across children, but each one holds a different concrete type
func (m Model) updatePIVChild(msg tea.Msg) (tea.Model, tea.Cmd) {
	child, cmd := m.pivChild.Update(msg)
	m.pivChild = &child
	if !m.pivChild.Done() {
		return m, cmd
	}
	if m.pivChild.Canceled() {
		if err := m.pivChild.errorMsg; err != "" {
			m.errorMsg = err
		}
		m.pivChild = nil
		m.state = stateProviderSelect
		return m, cmd
	}
	result, err := m.pivChild.Result()
	m.pivChild = nil
	return m.handleEnrollResult(enrollMsg{enrollment: result, err: err})
}

// updateSSHKeyChild mirrors updatePassphraseChild for the SSH key sub-model.
//
//nolint:dupl // structurally identical across children, but each one holds a different concrete type
func (m Model) updateSSHKeyChild(msg tea.Msg) (tea.Model, tea.Cmd) {
	child, cmd := m.sshKeyChild.Update(msg)
	m.sshKeyChild = &child
	if !m.sshKeyChild.Done() {
		return m, cmd
	}
	if m.sshKeyChild.Canceled() {
		if err := m.sshKeyChild.errorMsg; err != "" {
			m.errorMsg = err
		}
		m.sshKeyChild = nil
		m.state = stateProviderSelect
		return m, cmd
	}
	result, err := m.sshKeyChild.Result()
	m.sshKeyChild = nil
	return m.handleEnrollResult(enrollMsg{enrollment: result, err: err})
}

// updateSSHAgentChild mirrors updatePassphraseChild for the SSH agent sub-model.
//
//nolint:dupl // structurally identical across children, but each one holds a different concrete type
func (m Model) updateSSHAgentChild(msg tea.Msg) (tea.Model, tea.Cmd) {
	child, cmd := m.sshAgentChild.Update(msg)
	m.sshAgentChild = &child
	if !m.sshAgentChild.Done() {
		return m, cmd
	}
	if m.sshAgentChild.Canceled() {
		if err := m.sshAgentChild.errorMsg; err != "" {
			m.errorMsg = err
		}
		m.sshAgentChild = nil
		m.state = stateProviderSelect
		return m, cmd
	}
	result, err := m.sshAgentChild.Result()
	m.sshAgentChild = nil
	return m.handleEnrollResult(enrollMsg{enrollment: result, err: err})
}

// updateFIDO2Child mirrors updatePassphraseChild for the FIDO2 sub-model.
//
//nolint:dupl // structurally identical across children, but each one holds a different concrete type
func (m Model) updateFIDO2Child(msg tea.Msg) (tea.Model, tea.Cmd) {
	child, cmd := m.fido2Child.Update(msg)
	m.fido2Child = &child

	if !m.fido2Child.Done() {
		return m, cmd
	}

	if m.fido2Child.Canceled() {
		// Preserve whatever error the child surfaced (e.g. "no FIDO2 devices
		// detected") so the provider-select screen can show it.
		if err := m.fido2Child.errorMsg; err != "" {
			m.errorMsg = err
		}
		m.fido2Child = nil
		m.state = stateProviderSelect
		return m, cmd
	}

	result, err := m.fido2Child.Result()
	m.fido2Child = nil
	return m.handleEnrollResult(enrollMsg{enrollment: result, err: err})
}

func (m Model) handleKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	key := msg.String()

	switch m.state {
	case stateProviderSelect:
		return m.handleProviderSelect(key)
	case stateProviderSetup:
		return m.handleProviderSetup(key)
	case stateProviderOrder:
		return m.handleProviderOrder(key)
	case stateEnrollComplete:
		if key == keyEnter {
			m.statusMsg = ""
			m.state = stateProviderSelect
		}
		return m, nil
	case stateDone, stateError:
		if key == keyEnter || key == "q" {
			return m, tea.Quit
		}
	}

	return m, nil
}

func (m Model) handleProviderSelect(key string) (tea.Model, tea.Cmd) {
	switch key {
	case keyUp, "k":
		if m.cursor > 0 {
			m.cursor--
		}
	case keyDown, "j":
		if m.cursor < len(m.providers)-1 {
			m.cursor++
		}
	case keyEnter:
		return m.selectProvider()
	case "d":
		return m.handleDoneKey()
	case "+", "=":
		if m.threshold < len(m.enrollments)+10 { // reasonable upper bound
			m.threshold++
		}
	case "-", "_":
		if m.threshold > 2 {
			m.threshold--
		}
	}
	return m, nil
}

// selectProvider transitions to setup for the currently highlighted provider,
// loading its configurable options (if any) and surfacing an early warning
// when the provider has nothing to configure but cannot be enrolled.
func (m Model) selectProvider() (tea.Model, tea.Cmd) {
	m.selectedProvider = m.providers[m.cursor]
	m.idInput = m.defaultID()
	m.configFocus = 0
	m.editingName = false

	if cp, ok := m.selectedProvider.(provider.ConfigurableProvider); ok {
		opts := cp.EnrollOptions()
		if len(opts) > 0 {
			m.configOptions = opts
			m.configValues = make(map[string]string, len(opts))
			for _, o := range opts {
				m.configValues[o.Key] = o.Default
			}
		} else {
			m.configOptions = nil
			m.configValues = nil
		}
	} else {
		m.configOptions = nil
		m.configValues = nil
	}

	// If provider has no options and reports a warning, show it on the select
	// screen instead of entering setup (e.g. no PKCS#11 modules installed).
	if m.configOptions == nil {
		if ow, ok := m.selectedProvider.(provider.OptionWarner); ok {
			if w := ow.EnrollWarning(nil); w != "" {
				m.errorMsg = w
				return m, nil
			}
		}
	}

	m.state = stateProviderSetup
	return m, nil
}

// handleDoneKey fires when the user presses `d` on the provider-select screen:
// advance to ordering if enough providers are enrolled, otherwise surface a
// message explaining how many more are needed.
func (m Model) handleDoneKey() (tea.Model, tea.Cmd) {
	if len(m.enrollments) >= m.threshold {
		sortEnrollmentsByPriority(m.enrollments)
		m.orderCursor = 0
		m.state = stateProviderOrder
		return m, nil
	}
	need := m.threshold - len(m.enrollments)
	switch {
	case len(m.enrollments) == 0:
		m.errorMsg = fmt.Sprintf("Need at least %d providers (threshold %d); add %d to continue.",
			m.threshold, m.threshold, m.threshold)
	case need == 1:
		m.errorMsg = fmt.Sprintf("Threshold is %d; add 1 more provider to continue.", m.threshold)
	default:
		m.errorMsg = fmt.Sprintf("Threshold is %d; add %d more providers to continue.",
			m.threshold, need)
	}
	return m, nil
}

// totalSetupRows returns the number of focusable rows: 1 (name) + options.
func (m Model) totalSetupRows() int {
	return 1 + len(m.configOptions)
}

//nolint:gocyclo // switch-based tea handler, complexity is inherent to state machine dispatch
func (m Model) handleProviderSetup(key string) (tea.Model, tea.Cmd) {
	// When editing the name, only handle text input keys
	if m.editingName {
		return m.handleNameEdit(key)
	}

	totalRows := m.totalSetupRows()

	switch key {
	case keyEnter:
		id := m.idInput
		if id == "" {
			id = m.defaultID()
		}
		for _, e := range m.enrollments {
			if e.ID == id {
				m.errorMsg = fmt.Sprintf("ID %q already in use", id)
				return m, nil
			}
		}
		m.errorMsg = ""
		m.selectedID = id
		return m.startEnrollFlow()

	case keyEscape:
		m.state = stateProviderSelect
		m.errorMsg = ""
		m.configOptions = nil
		m.configValues = nil
		return m, nil

	case keyUp, "k":
		if m.configFocus > 0 {
			m.configFocus--
		}
		return m, nil

	case keyDown, "j":
		if m.configFocus < totalRows-1 {
			m.configFocus++
		}
		return m, nil

	case "tab":
		m.configFocus = (m.configFocus + 1) % totalRows
		return m, nil

	case keyLeft, keyRight:
		if m.configFocus > 0 && m.configFocus <= len(m.configOptions) {
			m.cycleOption(m.configFocus-1, key == keyRight)
			return m, nil
		}
	}

	// Enter name edit mode
	if m.configFocus == 0 && key == "n" {
		m.editingName = true
		return m, nil
	}

	// Shortcut keys for options
	for i, opt := range m.configOptions {
		if key == opt.Shortcut {
			m.cycleOption(i, true)
			return m, nil
		}
	}

	return m, nil
}

func (m *Model) cycleOption(idx int, forward bool) {
	opt := m.configOptions[idx]
	current := m.configValues[opt.Key]
	for i, v := range opt.Values {
		if v == current {
			if forward {
				m.configValues[opt.Key] = opt.Values[(i+1)%len(opt.Values)]
			} else {
				m.configValues[opt.Key] = opt.Values[(i-1+len(opt.Values))%len(opt.Values)]
			}
			return
		}
	}
}

func (m Model) handleNameEdit(key string) (tea.Model, tea.Cmd) {
	switch key {
	case keyEnter:
		m.editingName = false
		if m.idInput == "" {
			m.idInput = m.defaultID()
		}
		return m, nil
	case keyEscape:
		m.editingName = false
		m.state = stateProviderSelect
		m.errorMsg = ""
		m.configOptions = nil
		m.configValues = nil
		return m, nil
	case keyBackspace:
		if m.idInput != "" {
			m.idInput = m.idInput[:len(m.idInput)-1]
		}
		return m, nil
	default:
		if len(key) == 1 {
			m.idInput += key
		}
		return m, nil
	}
}

// startEnrollFlow routes to the correct enrollment path based on provider type.
func (m Model) startEnrollFlow() (tea.Model, tea.Cmd) {
	switch m.selectedProvider.Type() {
	case "passphrase":
		child := newEnrollPassphrase(m.ctx, m.selectedProvider, m.selectedID, m.configValues)
		m.passphraseChild = &child
		m.state = stateEnrollPassphrase
		m.errorMsg = ""
		return m, child.Init()

	case typeFIDO2:
		child := newEnrollFIDO2(m.ctx, m.selectedProvider, m.selectedID, m.configValues)
		m.fido2Child = &child
		m.state = stateEnrollFIDO2
		m.errorMsg = ""
		return m, child.Init()

	case "ssh-agent":
		child := newEnrollSSHAgent(m.ctx, m.selectedProvider, m.selectedID, m.configValues)
		m.sshAgentChild = &child
		m.state = stateEnrollSSHAgent
		m.errorMsg = ""
		return m, child.Init()

	case "sshkey":
		child := newEnrollSSHKey(m.ctx, m.selectedProvider, m.selectedID, m.configValues)
		m.sshKeyChild = &child
		m.state = stateEnrollSSHKey
		m.errorMsg = ""
		return m, child.Init()

	case "piv":
		child := newEnrollPIV(m.ctx, m.selectedProvider, m.selectedID, m.configValues)
		m.pivChild = &child
		m.state = stateEnrollPIV
		m.errorMsg = ""
		return m, child.Init()

	case typeRecovery:
		return m.startBackgroundEnroll()

	case "passkey":
		return m.startBackgroundEnroll()

	default:
		// Unknown provider — try background enrollment
		return m.startBackgroundEnroll()
	}
}

// startBackgroundEnroll runs enrollment in a goroutine with silent context.
func (m Model) startBackgroundEnroll() (tea.Model, tea.Cmd) {
	m.state = stateEnrolling
	m.statusMsg = fmt.Sprintf("Enrolling %s...", m.selectedProvider.Type())

	ctx := m.enrollContext()
	ctx = context.WithValue(ctx, provider.CtxSilent, true)

	p := m.selectedProvider
	id := m.selectedID
	return m, func() tea.Msg {
		e, err := enrollment.EnrollProvider(ctx, p, id)
		return enrollMsg{enrollment: e, err: err}
	}
}

// renderProgressLog writes the progress log as a checklist: completed steps
// get a dim check, and the final entry (the currently-active step) is
// highlighted so the user can see what the provider is waiting on.
func (m Model) renderProgressLog(b *strings.Builder) {
	if len(m.progressLog) == 0 {
		if m.statusMsg != "" {
			b.WriteString(highlightStyle.Render(m.statusMsg))
			b.WriteString("\n")
		}
		return
	}
	last := len(m.progressLog) - 1
	for i, step := range m.progressLog {
		if i < last {
			b.WriteString(successStyle.Render("  ✓ "))
			b.WriteString(dimStyle.Render(step))
		} else {
			b.WriteString(highlightStyle.Render("  • "))
			b.WriteString(highlightStyle.Render(step))
		}
		b.WriteString("\n")
	}
}

// enrollContext returns the model context with any configured enroll options applied.
func (m Model) enrollContext() context.Context {
	return provider.WithEnrollOptions(m.ctx, m.configValues)
}

func (m Model) handleEnrollResult(msg enrollMsg) (tea.Model, tea.Cmd) {
	m.progressLog = nil

	if msg.err != nil {
		m.errorMsg = msg.err.Error()
		m.state = stateProviderSelect
		return m, nil
	}

	m.enrollments = append(m.enrollments, *msg.enrollment)
	m.errorMsg = ""

	if msg.enrollment.Message != "" {
		m.statusMsg = msg.enrollment.Message
		m.state = stateEnrollComplete
	} else {
		m.statusMsg = ""
		m.state = stateProviderSelect
	}
	return m, nil
}

func (m Model) finalize() (tea.Model, tea.Cmd) {
	m.state = stateDone
	m.statusMsg = "Building profile..."

	err := enrollment.BuildProfile(m.profileName, m.threshold, m.enrollments)
	if err != nil {
		m.state = stateError
		m.errorMsg = err.Error()
		return m, nil
	}

	path, _ := config.Path(m.profileName)
	m.statusMsg = fmt.Sprintf("Profile written to %s", path)
	return m, nil
}

func (m Model) defaultID() string {
	typeName := m.selectedProvider.Type()
	count := 1
	for _, e := range m.enrollments {
		if e.Provider.Type() == typeName {
			count++
		}
	}
	return fmt.Sprintf("%s-%d", typeName, count)
}

// enrolledDetail returns a short summary of notable config for an enrollment.
func enrolledDetail(e enrollment.Enrollment) string {
	var details []string
	if e.Provider.Type() == typeFIDO2 {
		if uv, ok := e.Params["uv"]; ok && uv != "" && uv != uvPreferred {
			details = append(details, "uv:"+uv)
		}
	}
	// Show non-default argon params for passphrase/recovery
	if e.Provider.Type() == "passphrase" || e.Provider.Type() == typeRecovery {
		if t := e.Params["argon_time"]; t != "" && t != "3" {
			details = append(details, "t:"+t)
		}
		if m := e.Params["argon_memory"]; m != "" && m != "262144" {
			details = append(details, "m:"+m+"K")
		}
		if p := e.Params["argon_threads"]; p != "" && p != "4" {
			details = append(details, "p:"+p)
		}
	}
	if len(details) == 0 {
		return e.Provider.Type()
	}
	return e.Provider.Type() + ", " + strings.Join(details, ", ")
}

// renderOptionValues renders all values for an option with the active one highlighted.
func renderOptionValues(values []string, active string) string {
	var parts []string
	for _, v := range values {
		if v == active {
			parts = append(parts, highlightStyle.Render(v))
		} else {
			parts = append(parts, dimStyle.Render(v))
		}
	}
	return strings.Join(parts, dimStyle.Render(" | "))
}

//nolint:gocyclo,funlen // bubbletea View methods are inherently complex state-machine renderers
func (m Model) View() tea.View {
	if m.quitting {
		v := tea.NewView("")
		v.AltScreen = true
		return v
	}

	var b strings.Builder

	b.WriteString(titleStyle.Render("cryptkey init"))
	b.WriteString("  ")
	b.WriteString(subtitleStyle.Render(m.profileName))
	b.WriteString("\n\n")

	// Show enrolled providers
	if len(m.enrollments) > 0 {
		b.WriteString(dimStyle.Render("Enrolled:"))
		b.WriteString("\n")
		for _, e := range m.enrollments {
			b.WriteString(successStyle.Render("  ✓ "))
			fmt.Fprintf(&b, "%s (%s)\n", e.ID, enrolledDetail(e))
		}
		b.WriteString("\n")
	}

	switch m.state {
	case stateProviderSelect:
		fmt.Fprintf(&b, "Threshold: %s  %s\n\n",
			highlightStyle.Render(strconv.Itoa(m.threshold)),
			dimStyle.Render("+/- to adjust"))

		remaining := m.threshold - len(m.enrollments)
		if remaining > 0 {
			fmt.Fprintf(&b, "Select a provider (%d more needed):\n\n", remaining)
		} else {
			b.WriteString("Select a provider, or press ")
			b.WriteString(highlightStyle.Render("d"))
			b.WriteString(" to finish:\n\n")
		}

		if w := enrollment.RecoveryWarning(m.threshold, m.enrollments); w != "" {
			b.WriteString(warningStyle.Render(w))
			b.WriteString("\n\n")
		}

		if w := enrollment.NonInteractiveWarning(m.threshold, m.enrollments); w != "" {
			b.WriteString(warningStyle.Render(w))
			b.WriteString("\n\n")
		}

		for i, p := range m.providers {
			cursor := indentTwo
			style := lipgloss.NewStyle()
			if i == m.cursor {
				cursor = highlightStyle.Render("> ")
				style = highlightStyle
			}
			fmt.Fprintf(&b, "%s%s", cursor, style.Render(p.Type()))
			fmt.Fprintf(&b, "%s", dimStyle.Render(fmt.Sprintf(" — %s", p.Description())))
			b.WriteString("\n")
		}

		b.WriteString("\n")
		b.WriteString(dimStyle.Render("↑/↓ navigate • enter select • d done • ctrl+c quit"))

	case stateProviderSetup:
		fmt.Fprintf(&b, "Configure %s:\n\n", highlightStyle.Render(m.selectedProvider.Type()))

		// Name row
		namePrefix := indentTwo
		if m.configFocus == 0 {
			namePrefix = highlightStyle.Render("> ")
		}
		if m.editingName {
			fmt.Fprintf(&b, "%s%s %s%s",
				namePrefix,
				highlightStyle.Render("Name:"),
				m.idInput,
				highlightStyle.Render("█"))
		} else {
			nameStyle := lipgloss.NewStyle()
			if m.configFocus == 0 {
				nameStyle = highlightStyle
			}
			fmt.Fprintf(&b, "%s%s %s",
				namePrefix,
				nameStyle.Render("Name:"),
				m.idInput)
			if m.configFocus == 0 {
				b.WriteString(dimStyle.Render("  (n to rename)"))
			}
		}
		b.WriteString("\n")

		// Option rows
		for i, opt := range m.configOptions {
			val := m.configValues[opt.Key]
			prefix := indentTwo
			labelStyle := lipgloss.NewStyle()
			focused := m.configFocus == i+1
			if focused {
				prefix = highlightStyle.Render("> ")
				labelStyle = highlightStyle
			}
			fmt.Fprintf(&b, "%s[%s] %s: %s\n",
				prefix,
				highlightStyle.Render(opt.Shortcut),
				labelStyle.Render(opt.Label),
				renderOptionValues(opt.Values, val))

			// Show contextual help for the focused option's current value
			if focused {
				if help, ok := opt.ValueHelp[val]; ok {
					fmt.Fprintf(&b, "      %s\n", dimStyle.Render(help))
				} else if opt.Description != "" {
					fmt.Fprintf(&b, "      %s\n", dimStyle.Render(opt.Description))
				}
			}
		}

		// Show warning for high-cost option combinations
		if ow, ok := m.selectedProvider.(provider.OptionWarner); ok {
			if w := ow.EnrollWarning(m.configValues); w != "" {
				b.WriteString("\n")
				b.WriteString(warningStyle.Render(w))
			}
		}

		b.WriteString("\n")
		if m.editingName {
			b.WriteString(dimStyle.Render("type to edit • enter/escape to finish editing"))
		} else if len(m.configOptions) > 0 {
			b.WriteString(dimStyle.Render("↑/↓ focus • ←/→ cycle • shortcut to toggle • n rename • enter continue • escape back"))
		} else {
			b.WriteString(dimStyle.Render("n rename • enter continue • escape back"))
		}

	case stateEnrollPassphrase:
		if m.passphraseChild != nil {
			fmt.Fprintf(&b, "Passphrase enrollment for %s\n\n", highlightStyle.Render(m.selectedID))
			b.WriteString(m.passphraseChild.View())
		}

	case stateEnrollFIDO2:
		if m.fido2Child != nil {
			fmt.Fprintf(&b, "FIDO2 enrollment for %s\n\n", highlightStyle.Render(m.selectedID))
			b.WriteString(m.fido2Child.View())
		}

	case stateEnrollSSHAgent:
		if m.sshAgentChild != nil {
			fmt.Fprintf(&b, "SSH agent enrollment for %s\n\n", highlightStyle.Render(m.selectedID))
			b.WriteString(m.sshAgentChild.View())
		}

	case stateEnrollSSHKey:
		if m.sshKeyChild != nil {
			fmt.Fprintf(&b, "SSH key enrollment for %s\n\n", highlightStyle.Render(m.selectedID))
			b.WriteString(m.sshKeyChild.View())
		}

	case stateEnrollPIV:
		if m.pivChild != nil {
			fmt.Fprintf(&b, "PIV enrollment for %s\n\n", highlightStyle.Render(m.selectedID))
			b.WriteString(m.pivChild.View())
		}

	case stateProviderOrder:
		m.viewProviderOrder(&b)

	case stateEnrolling:
		m.renderProgressLog(&b)

	case stateEnrollComplete:
		last := m.enrollments[len(m.enrollments)-1]
		b.WriteString(successStyle.Render("✓ "))
		fmt.Fprintf(&b, "Enrolled %s\n\n", last.ID)

		if last.Provider.Type() == typeRecovery && m.statusMsg != "" {
			b.WriteString(warningStyle.Render("RECOVERY CODE — WRITE THIS DOWN"))
			b.WriteString("\n\n")
			b.WriteString("  ")
			b.WriteString(codeStyle.Render(m.statusMsg))
			b.WriteString("\n\n")
			b.WriteString(warningStyle.Render("This code will NOT be shown again."))
			b.WriteString("\n")
			b.WriteString(warningStyle.Render("Store it in a safe place (printed, written, photographed)."))
		} else if m.statusMsg != "" {
			b.WriteString(m.statusMsg)
		}
		b.WriteString("\n\n")
		b.WriteString(dimStyle.Render("Press enter to continue"))

	case stateDone:
		b.WriteString(successStyle.Render("✓ "))
		b.WriteString(m.statusMsg)
		b.WriteString("\n")
		fmt.Fprintf(&b, "  %d providers, threshold %d\n", len(m.enrollments), m.threshold)
		if w := enrollment.RecoveryWarning(m.threshold, m.enrollments); w != "" {
			b.WriteString("\n")
			b.WriteString(errorStyle.Render(w))
			b.WriteString("\n")
		}
		if w := enrollment.NonInteractiveWarning(m.threshold, m.enrollments); w != "" {
			b.WriteString("\n")
			b.WriteString(errorStyle.Render(w))
			b.WriteString("\n")
		}
		b.WriteString("\n")
		b.WriteString(dimStyle.Render("Press enter or q to exit"))

	case stateError:
		b.WriteString(errorStyle.Render("Error: "))
		b.WriteString(m.errorMsg)
		b.WriteString("\n\n")
		b.WriteString(dimStyle.Render("Press enter or q to exit"))
	}

	if m.errorMsg != "" && m.state != stateError && m.state != stateDone {
		b.WriteString("\n\n")
		b.WriteString(errorStyle.Render(m.errorMsg))
	}

	b.WriteString("\n")
	v := tea.NewView(b.String())
	v.AltScreen = true
	return v
}

// Enrollments returns the completed enrollments.
func (m Model) Enrollments() []enrollment.Enrollment {
	return m.enrollments
}

// Err returns the error if the model is in error state.
func (m Model) Err() error {
	if m.state == stateError {
		return fmt.Errorf("%s", m.errorMsg)
	}
	return nil
}

// Completed returns true if the profile was successfully written.
func (m Model) Completed() bool {
	return m.state == stateDone
}
