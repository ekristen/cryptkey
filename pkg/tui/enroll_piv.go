package tui

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"charm.land/bubbles/v2/textinput"
	tea "charm.land/bubbletea/v2"

	gopiv "github.com/go-piv/piv-go/v2/piv"

	"github.com/ekristen/cryptkey/pkg/enrollment"
	"github.com/ekristen/cryptkey/pkg/provider"
	"github.com/ekristen/cryptkey/pkg/provider/piv"
)

// enrollPIV is a self-contained sub-model for PIV enrollment: card scan →
// card select (if >1) → PIN entry → probe slot → (if slot occupied +
// mode=overwrite) typed confirmation → background enroll with progress.
type enrollPIV struct {
	ctx      context.Context
	provider provider.Provider
	id       string
	options  map[string]string

	state       pivState
	cards       []pivCardInfo
	cardCur     int
	pin         string
	pinInput    textinput.Model
	overwrite   string
	progressCh  chan string
	progressLog []string
	errorMsg    string

	result *enrollment.Enrollment
	err    error
}

type pivState int

const (
	pivStateScanning pivState = iota
	pivStateCardSelect
	pivStatePINEntry
	pivStateProbing
	pivStateOverwriteConfirm
	pivStateEnrolling
	pivStateDone
	pivStateCanceled
)

// pivCardInfo holds PIV card metadata for TUI display.
type pivCardInfo struct {
	Name   string
	Serial string
}

// --- messages ---

type pivCardsMsg struct {
	cards []pivCardInfo
	err   error
}

type pivSlotProbeMsg struct {
	hasKey bool
	err    error
}

type pivProgressMsg string

type pivEnrollCompletedMsg struct {
	result *enrollment.Enrollment
	err    error
}

const (
	pivOverwritePhrase = "confirm overwrite"
	pivDefaultSlotHex  = "9d"
)

// scanPIVCards returns a tea.Cmd that scans for PIV cards.
func scanPIVCards() tea.Msg {
	cards, err := piv.ListCards()
	if err != nil {
		return pivCardsMsg{err: err}
	}
	infos := make([]pivCardInfo, len(cards))
	for i, c := range cards {
		infos[i] = pivCardInfo{Name: c, Serial: piv.CardSerial(c)}
	}
	return pivCardsMsg{cards: infos}
}

func newEnrollPIV(ctx context.Context, p provider.Provider, id string, options map[string]string) enrollPIV {
	return enrollPIV{
		ctx:      ctx,
		provider: p,
		id:       id,
		options:  options,
		state:    pivStateScanning,
		pinInput: newPasswordInput(64),
	}
}

func (m enrollPIV) Init() tea.Cmd { return scanPIVCards }

func (m enrollPIV) Update(msg tea.Msg) (enrollPIV, tea.Cmd) {
	switch msg := msg.(type) {
	case pivCardsMsg:
		return m.handleCards(msg)
	case pivSlotProbeMsg:
		return m.handleSlotProbe(msg)
	case pivProgressMsg:
		m.progressLog = appendProgress(m.progressLog, string(msg))
		if m.progressCh != nil {
			return m, listenProgress(m.progressCh, func(s string) pivProgressMsg { return pivProgressMsg(s) })
		}
		return m, nil
	case pivEnrollCompletedMsg:
		m.result = msg.result
		m.err = msg.err
		m.state = pivStateDone
		return m, nil
	case tea.KeyMsg:
		switch m.state {
		case pivStateCardSelect:
			return m.handleCardSelect(msg.String())
		case pivStatePINEntry:
			return m.handlePINEntry(msg)
		case pivStateOverwriteConfirm:
			return m.handleOverwriteConfirm(msg)
		}
	}

	if m.state == pivStatePINEntry {
		var cmd tea.Cmd
		m.pinInput, cmd = m.pinInput.Update(msg)
		return m, cmd
	}
	return m, nil
}

//nolint:dupl // structurally similar to enrollFIDO2.handleDevices, but on a different hardware type
func (m enrollPIV) handleCards(msg pivCardsMsg) (enrollPIV, tea.Cmd) {
	if msg.err != nil {
		m.errorMsg = msg.err.Error()
		m.state = pivStateCanceled
		return m, nil
	}
	if len(msg.cards) == 0 {
		m.errorMsg = "No PIV-compatible cards detected — insert a YubiKey or smart card and try again"
		m.state = pivStateCanceled
		return m, nil
	}
	m.cards = msg.cards
	if len(msg.cards) == 1 {
		m.cardCur = 0
		return m.afterCard()
	}
	m.state = pivStateCardSelect
	return m, nil
}

func (m enrollPIV) handleCardSelect(key string) (enrollPIV, tea.Cmd) {
	switch key {
	case keyUp, "k":
		if m.cardCur > 0 {
			m.cardCur--
		}
	case keyDown, "j":
		if m.cardCur < len(m.cards)-1 {
			m.cardCur++
		}
	case keyEnter:
		return m.afterCard()
	case keyEscape:
		m.state = pivStateCanceled
	}
	return m, nil
}

func (m enrollPIV) afterCard() (enrollPIV, tea.Cmd) {
	m.pinInput.SetValue("")
	m.state = pivStatePINEntry
	return m, m.pinInput.Focus()
}

//nolint:dupl // mirror of unlockPIV.handlePINEntry — distinct phase/state
func (m enrollPIV) handlePINEntry(msg tea.KeyMsg) (enrollPIV, tea.Cmd) {
	switch msg.String() {
	case keyEnter:
		m.pin = m.pinInput.Value()
		m.pinInput.SetValue("")
		m.pinInput.Blur()
		m.errorMsg = ""
		return m.probeSlot()
	case keyEscape:
		m.pinInput.SetValue("")
		m.pinInput.Blur()
		m.state = pivStateCanceled
		return m, nil
	default:
		var cmd tea.Cmd
		m.pinInput, cmd = m.pinInput.Update(msg)
		return m, cmd
	}
}

func (m enrollPIV) probeSlot() (enrollPIV, tea.Cmd) {
	m.state = pivStateProbing
	m.progressLog = nil
	m.progressLog = appendProgress(m.progressLog, "Checking slot for existing key material...")

	card := m.cards[m.cardCur]
	slotHex := m.options["slot"]
	if slotHex == "" {
		slotHex = pivDefaultSlotHex
	}
	return m, func() tea.Msg {
		slot, err := parseSlotForProbe(slotHex)
		if err != nil {
			return pivSlotProbeMsg{err: err}
		}
		pub, err := piv.SlotHasKey(card.Name, slot)
		if err != nil {
			return pivSlotProbeMsg{err: err}
		}
		return pivSlotProbeMsg{hasKey: pub != nil}
	}
}

func (m enrollPIV) handleSlotProbe(msg pivSlotProbeMsg) (enrollPIV, tea.Cmd) {
	if msg.err != nil {
		m.errorMsg = msg.err.Error()
		m.state = pivStateCanceled
		return m, nil
	}
	if !msg.hasKey {
		return m.startEnroll(false)
	}
	if m.options["mode"] == "overwrite" {
		m.overwrite = ""
		m.state = pivStateOverwriteConfirm
		return m, nil
	}
	return m.startEnroll(false)
}

func (m enrollPIV) handleOverwriteConfirm(msg tea.KeyMsg) (enrollPIV, tea.Cmd) {
	switch msg.String() {
	case keyEnter:
		if strings.TrimSpace(m.overwrite) == pivOverwritePhrase {
			m.errorMsg = ""
			return m.startEnroll(true)
		}
		m.errorMsg = fmt.Sprintf(`type %q exactly to proceed, or esc to cancel`, pivOverwritePhrase)
		return m, nil
	case keyEscape:
		m.overwrite = ""
		m.state = pivStateCanceled
		m.errorMsg = ""
		return m, nil
	case keyBackspace, "ctrl+h":
		if m.overwrite != "" {
			m.overwrite = m.overwrite[:len(m.overwrite)-1]
		}
		return m, nil
	}
	if t := msg.Key().Text; t != "" {
		m.overwrite += t
	}
	return m, nil
}

func (m enrollPIV) startEnroll(overwrite bool) (enrollPIV, tea.Cmd) {
	m.state = pivStateEnrolling
	card := m.cards[m.cardCur]
	m.progressLog = appendProgress(m.progressLog, fmt.Sprintf("Enrolling PIV key on %s (serial: %s)", card.Name, card.Serial))

	ctx := provider.WithEnrollOptions(m.ctx, m.options)
	ctx = context.WithValue(ctx, provider.CtxSilent, true)
	ctx = context.WithValue(ctx, provider.CtxPIVSerial, card.Serial)
	// Always set the PIN key — even when empty — so the provider treats
	// "use default PIN" as a pre-collected answer and does not fall back
	// to prompting on /dev/tty (which would clobber the TUI).
	ctx = context.WithValue(ctx, provider.CtxPIVPIN, m.pin)
	if overwrite {
		ctx = context.WithValue(ctx, provider.CtxPIVOverwrite, true)
	}

	progressCh := make(chan string, 4)
	m.progressCh = progressCh
	ctx = context.WithValue(ctx, provider.CtxProgressFunc, func(msg string) {
		progressCh <- msg
	})

	p := m.provider
	id := m.id
	enrollCmd := func() tea.Msg {
		res, err := enrollment.EnrollProvider(ctx, p, id)
		close(progressCh)
		return pivEnrollCompletedMsg{result: res, err: err}
	}
	return m, tea.Batch(enrollCmd, listenProgress(progressCh, func(s string) pivProgressMsg { return pivProgressMsg(s) }))
}

func (m enrollPIV) View() string {
	var b strings.Builder
	switch m.state {
	case pivStateScanning:
		b.WriteString(highlightStyle.Render("Scanning for PIV cards..."))
		b.WriteString("\n")
	case pivStateCardSelect:
		b.WriteString("Select PIV card:\n\n")
		for i, c := range m.cards {
			cursor := indentTwo
			style := dimStyle
			if i == m.cardCur {
				cursor = highlightStyle.Render("> ")
				style = highlightStyle
			}
			label := c.Name
			if c.Serial != "unknown" {
				label = fmt.Sprintf("%s (serial: %s)", c.Name, c.Serial)
			}
			fmt.Fprintf(&b, "%s%s\n", cursor, style.Render(label))
		}
		b.WriteString("\n")
		b.WriteString(dimStyle.Render("↑/↓ navigate • enter select • esc cancel"))
	case pivStatePINEntry:
		b.WriteString("Enter PIV PIN (or press enter for default 123456):\n\n")
		b.WriteString(promptStyle.Render("> "))
		b.WriteString(m.pinInput.View())
		b.WriteString("\n\n")
		b.WriteString(dimStyle.Render("enter continue • esc cancel"))
	case pivStateProbing, pivStateEnrolling:
		renderProgressChecklist(&b, m.progressLog)
	case pivStateOverwriteConfirm:
		slotHex := m.options["slot"]
		if slotHex == "" {
			slotHex = pivDefaultSlotHex
		}
		b.WriteString(warningStyle.Render("WARNING: Slot " + slotHex + " already contains key material!"))
		b.WriteString("\n\n")
		b.WriteString("Continuing will ")
		b.WriteString(errorStyle.Render("permanently destroy"))
		b.WriteString(" the existing key.\n")
		b.WriteString("Any certificates or services using this slot will stop working.\n\n")
		fmt.Fprintf(&b, `Type %s to proceed:`, highlightStyle.Render(`"`+pivOverwritePhrase+`"`))
		b.WriteString("\n\n")
		b.WriteString(promptStyle.Render("> "))
		b.WriteString(m.overwrite)
		b.WriteString(highlightStyle.Render("█"))
		b.WriteString("\n\n")
		b.WriteString(dimStyle.Render("enter confirm • esc cancel"))
	case pivStateDone, pivStateCanceled:
		// Parent unmounts once Done() is true.
	}
	if m.errorMsg != "" {
		fmt.Fprintf(&b, "\n%s\n", errorStyle.Render(m.errorMsg))
	}
	return b.String()
}

func (m enrollPIV) Done() bool {
	return m.state == pivStateDone || m.state == pivStateCanceled
}

func (m enrollPIV) Canceled() bool {
	return m.state == pivStateCanceled
}

func (m enrollPIV) Result() (*enrollment.Enrollment, error) {
	return m.result, m.err
}

// parseSlotForProbe converts a hex slot string to a piv.Slot (duplicated here
// to avoid exporting the provider's internal parseSlot).
func parseSlotForProbe(hexStr string) (gopiv.Slot, error) {
	hexStr = strings.TrimPrefix(strings.ToLower(hexStr), "0x")
	switch hexStr {
	case "9a":
		return gopiv.SlotAuthentication, nil
	case "9c":
		return gopiv.SlotSignature, nil
	case "9d":
		return gopiv.SlotKeyManagement, nil
	case "9e":
		return gopiv.SlotCardAuthentication, nil
	}
	val, err := strconv.ParseUint(hexStr, 16, 8)
	if err != nil {
		return gopiv.Slot{}, fmt.Errorf("piv: invalid slot %q", hexStr)
	}
	if val >= 0x82 && val <= 0x95 {
		slot, ok := gopiv.RetiredKeyManagementSlot(uint32(val))
		if !ok {
			return gopiv.Slot{}, fmt.Errorf("piv: unsupported retired slot 0x%s", hexStr)
		}
		return slot, nil
	}
	return gopiv.Slot{}, fmt.Errorf("piv: unsupported slot 0x%s", hexStr)
}
