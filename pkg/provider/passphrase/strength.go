package passphrase

import (
	"fmt"

	zxcvbn "github.com/nbutton23/zxcvbn-go"
)

// Strength describes the estimated resistance of a passphrase to offline
// brute force. Cryptkey uses zxcvbn's classifier under the hood; the scores
// map roughly to:
//
//	0 too guessable          ( < 10^3 guesses )
//	1 very guessable         ( < 10^6 guesses )
//	2 somewhat guessable     ( < 10^8 guesses )   ← default "weak" threshold
//	3 safely unguessable     ( < 10^10 guesses )
//	4 very unguessable       ( >= 10^10 guesses )
//
// Cryptkey's Argon2id stretching adds ~1–2 seconds per guess on top of
// zxcvbn's estimate, so a score of 2 is already expensive to attack in
// practice. We still warn below score 3 so users making a throwaway test
// profile aren't surprised when a determined attacker on rented GPU time
// eventually wins.
type Strength struct {
	Score        int     // 0..4; higher is stronger
	Entropy      float64 // bits
	CrackDisplay string  // human-readable crack-time estimate (zxcvbn's own label)
}

// ScoreThreshold is the minimum zxcvbn score cryptkey considers "not weak"
// for enrollment-time warnings. Scores at or above this pass silently.
const ScoreThreshold = 3

// ScorePassphrase returns a Strength estimate for the given passphrase. The
// check runs entirely offline against zxcvbn's bundled dictionary; no network
// calls, no disk I/O beyond the already-loaded process image.
//
// Passing the []byte (rather than a string) keeps the hot path aligned with
// the rest of cryptkey's secret hygiene. zxcvbn itself takes a string for its
// API; we construct one here and accept the immutable-string window as the
// cost of using the library.
func ScorePassphrase(pass []byte) Strength {
	if len(pass) == 0 {
		return Strength{Score: 0, CrackDisplay: "instant"}
	}
	m := zxcvbn.PasswordStrength(string(pass), nil)
	return Strength{
		Score:        m.Score,
		Entropy:      m.Entropy,
		CrackDisplay: m.CrackTimeDisplay,
	}
}

// IsWeak reports whether a Strength is below the warn threshold.
func (s Strength) IsWeak() bool { return s.Score < ScoreThreshold }

// Label returns a short human label for the score ("weak", "fair", "strong",
// "very strong") — suitable for inline display in both TUI and plain-CLI
// prompts.
func (s Strength) Label() string {
	switch s.Score {
	case 0, 1:
		return "weak"
	case 2:
		return "fair"
	case 3:
		return "strong"
	case 4:
		return "very strong"
	default:
		return fmt.Sprintf("score %d", s.Score)
	}
}
