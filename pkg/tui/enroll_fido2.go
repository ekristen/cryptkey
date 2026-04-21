package tui

import (
	"context"
	"fmt"
	"strings"

	"charm.land/bubbles/v2/textinput"
	tea "charm.land/bubbletea/v2"

	"github.com/ekristen/cryptkey/pkg/enrollment"
	"github.com/ekristen/cryptkey/pkg/provider"
	"github.com/ekristen/cryptkey/pkg/provider/fido2"
)

// enrollFIDO2 is a self-contained bubbletea sub-model for enrolling a FIDO2
// provider: device scan → device select (if >1 device) → PIN entry (if UV
// requires it) → touch credential → touch derive → done.
//
// The actual enrollment goroutine runs inside the sub-model so the
// "Touch your key..." progress messages stay scoped to this component.
// Parents compose it the same way they compose enrollPassphrase.
type enrollFIDO2 struct {
	ctx      context.Context
	provider provider.Provider
	id       string
	options  map[string]string

	state       fido2State
	devices     []fido2.DeviceInfo
	deviceCur   int
	pin         string
	input       textinput.Model
	progressCh  chan string
	progressLog []string
	errorMsg    string

	result *enrollment.Enrollment
	err    error
}

type fido2State int

const (
	fido2StateScanning fido2State = iota
	fido2StateDeviceSelect
	fido2StatePINEntry
	fido2StateEnrolling
	fido2StateDone
	fido2StateCanceled
)

// --- messages ---

// fido2DevicesMsg is returned by the device scan command.
type fido2DevicesMsg struct {
	devices []fido2.DeviceInfo
	err     error
}

// fido2ProgressMsg carries a progress update from the FIDO2 enrollment goroutine.
type fido2ProgressMsg string

// fido2EnrollCompletedMsg is emitted when the background enroll finishes.
type fido2EnrollCompletedMsg struct {
	result *enrollment.Enrollment
	err    error
}

// scanFIDO2Devices returns a tea.Cmd that scans for FIDO2 devices.
func scanFIDO2Devices() tea.Msg {
	devices, err := fido2.ListDevices()
	return fido2DevicesMsg{devices: devices, err: err}
}

// newEnrollFIDO2 builds the sub-model. Init() kicks off the device scan.
func newEnrollFIDO2(ctx context.Context, p provider.Provider, id string, options map[string]string) enrollFIDO2 {
	return enrollFIDO2{
		ctx:      ctx,
		provider: p,
		id:       id,
		options:  options,
		state:    fido2StateScanning,
		input:    newPasswordInput(64),
	}
}

func (m enrollFIDO2) Init() tea.Cmd { return scanFIDO2Devices }

func (m enrollFIDO2) Update(msg tea.Msg) (enrollFIDO2, tea.Cmd) {
	switch msg := msg.(type) {
	case fido2DevicesMsg:
		return m.handleDevices(msg)
	case fido2ProgressMsg:
		m.progressLog = appendProgress(m.progressLog, string(msg))
		if m.progressCh != nil {
			return m, listenProgress(m.progressCh, func(s string) fido2ProgressMsg { return fido2ProgressMsg(s) })
		}
		return m, nil
	case fido2EnrollCompletedMsg:
		m.result = msg.result
		m.err = msg.err
		m.state = fido2StateDone
		return m, nil
	case tea.KeyMsg:
		switch m.state {
		case fido2StateDeviceSelect:
			return m.handleDeviceSelect(msg.String())
		case fido2StatePINEntry:
			return m.handlePINEntry(msg)
		}
	}

	// Forward cursor-blink / other textinput messages while PIN entry is active.
	if m.state == fido2StatePINEntry {
		var cmd tea.Cmd
		m.input, cmd = m.input.Update(msg)
		return m, cmd
	}
	return m, nil
}

//nolint:dupl // structurally similar to enrollPIV.handleCards, but on a different hardware type
func (m enrollFIDO2) handleDevices(msg fido2DevicesMsg) (enrollFIDO2, tea.Cmd) {
	if msg.err != nil {
		m.errorMsg = msg.err.Error()
		m.state = fido2StateCanceled
		return m, nil
	}
	if len(msg.devices) == 0 {
		m.errorMsg = "No FIDO2 devices detected — insert a key and try again"
		m.state = fido2StateCanceled
		return m, nil
	}
	m.devices = msg.devices
	if len(msg.devices) == 1 {
		m.deviceCur = 0
		return m.afterDevice()
	}
	m.state = fido2StateDeviceSelect
	return m, nil
}

func (m enrollFIDO2) handleDeviceSelect(key string) (enrollFIDO2, tea.Cmd) {
	switch key {
	case keyUp, "k":
		if m.deviceCur > 0 {
			m.deviceCur--
		}
	case keyDown, "j":
		if m.deviceCur < len(m.devices)-1 {
			m.deviceCur++
		}
	case keyEnter:
		return m.afterDevice()
	case keyEscape:
		m.state = fido2StateCanceled
	}
	return m, nil
}

// afterDevice transitions from device selection to PIN entry (or straight to
// enrollment when UV is discouraged).
func (m enrollFIDO2) afterDevice() (enrollFIDO2, tea.Cmd) {
	uv := m.options["uv"]
	if uv == "" {
		uv = uvPreferred
	}
	if uv == uvDiscouraged {
		return m.startEnroll()
	}
	m.state = fido2StatePINEntry
	m.input.SetValue("")
	// m.input.Focus() here is safe because the modified m is returned as
	// the first return value — the parent picks up focus=true.
	blink := m.input.Focus()
	return m, blink
}

func (m enrollFIDO2) handlePINEntry(msg tea.KeyMsg) (enrollFIDO2, tea.Cmd) {
	switch msg.String() {
	case keyEnter:
		m.pin = m.input.Value()
		m.input.SetValue("")
		m.input.Blur()
		uv := m.options["uv"]
		if uv == uvRequired && m.pin == "" {
			m.errorMsg = "PIN is required"
			return m, m.input.Focus()
		}
		m.errorMsg = ""
		return m.startEnroll()
	case keyEscape:
		m.input.SetValue("")
		m.input.Blur()
		m.state = fido2StateCanceled
		return m, nil
	default:
		var cmd tea.Cmd
		m.input, cmd = m.input.Update(msg)
		return m, cmd
	}
}

// startEnroll kicks off the background FIDO2 enrollment with a progress
// channel so the user sees "Touch your key..." updates as the device is
// prodded.
func (m enrollFIDO2) startEnroll() (enrollFIDO2, tea.Cmd) {
	m.state = fido2StateEnrolling
	device := m.devices[m.deviceCur]

	ctx := provider.WithEnrollOptions(m.ctx, m.options)
	ctx = context.WithValue(ctx, provider.CtxSilent, true)
	ctx = context.WithValue(ctx, provider.CtxFIDO2DevicePath, device.Path)
	if m.pin != "" {
		ctx = context.WithValue(ctx, provider.CtxFIDO2PIN, m.pin)
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
		return fido2EnrollCompletedMsg{result: res, err: err}
	}

	return m, tea.Batch(enrollCmd, listenProgress(progressCh, func(s string) fido2ProgressMsg { return fido2ProgressMsg(s) }))
}

// View renders the component's own content. Parent supplies the header.
func (m enrollFIDO2) View() string {
	var b strings.Builder
	switch m.state {
	case fido2StateScanning:
		b.WriteString(highlightStyle.Render("Scanning for FIDO2 devices..."))
		b.WriteString("\n")
	case fido2StateDeviceSelect:
		b.WriteString("Select FIDO2 device:\n\n")
		for i, d := range m.devices {
			cursor := indentTwo
			style := dimStyle
			if i == m.deviceCur {
				cursor = highlightStyle.Render("> ")
				style = highlightStyle
			}
			fmt.Fprintf(&b, "%s%s\n", cursor, style.Render(d.DisplayName))
		}
		b.WriteString("\n")
		b.WriteString(dimStyle.Render("↑/↓ navigate • enter select • esc cancel"))
	case fido2StatePINEntry:
		uv := m.options["uv"]
		if uv == uvRequired {
			b.WriteString("Enter FIDO2 PIN:\n\n")
		} else {
			b.WriteString("Enter FIDO2 PIN (or press enter to skip):\n\n")
		}
		b.WriteString(promptStyle.Render("> "))
		b.WriteString(m.input.View())
		b.WriteString("\n\n")
		b.WriteString(dimStyle.Render("enter continue • esc cancel"))
	case fido2StateEnrolling:
		renderProgressChecklist(&b, m.progressLog)
	case fido2StateDone, fido2StateCanceled:
		// Parent unmounts once Done() is true.
	}
	if m.errorMsg != "" {
		fmt.Fprintf(&b, "\n%s\n", errorStyle.Render(m.errorMsg))
	}
	return b.String()
}

func (m enrollFIDO2) Done() bool {
	return m.state == fido2StateDone || m.state == fido2StateCanceled
}

func (m enrollFIDO2) Canceled() bool {
	return m.state == fido2StateCanceled
}

func (m enrollFIDO2) Result() (*enrollment.Enrollment, error) {
	return m.result, m.err
}
