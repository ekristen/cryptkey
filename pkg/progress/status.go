// Package progress provides structured status reporting for the derive flow.
package progress

// Status represents a provider's current state during derivation.
type Status int

const (
	StatusRunning   Status = iota // in progress
	StatusWaiting                 // blocking on hardware touch/browser
	StatusSucceeded               // derived successfully
	StatusSkipped                 // skipped with a reason
	StatusFailed                  // failed with an error
)

// Event is emitted to report provider progress during derivation.
type Event struct {
	Provider string // provider type, e.g. "ssh-agent", "fido2"
	ID       string // provider config ID, e.g. "fido2-1"
	Status   Status
	Message  string // e.g. "waiting for touch...", "no keys loaded", "timeout"
}
