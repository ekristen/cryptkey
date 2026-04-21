package passphrase

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestScorePassphrase_Weak(t *testing.T) {
	// The classic dictionary failures should all score below threshold.
	cases := []string{
		"password",
		"123456",
		"qwerty",
		"letmein",
		"admin",
		"monkey",
	}
	for _, pw := range cases {
		t.Run(pw, func(t *testing.T) {
			s := ScorePassphrase([]byte(pw))
			assert.True(t, s.IsWeak(), "expected %q to be weak (score %d)", pw, s.Score)
			assert.NotEmpty(t, s.Label())
			assert.NotEmpty(t, s.CrackDisplay)
		})
	}
}

func TestScorePassphrase_Strong(t *testing.T) {
	// A four-word diceware-style passphrase should clear the threshold.
	cases := []string{
		"correct-horse-battery-staple",
		"tangerine-galaxy-kettle-marble",
		"Zx9!pLmR2qVnT7#bEyWfKa",
	}
	for _, pw := range cases {
		t.Run(pw, func(t *testing.T) {
			s := ScorePassphrase([]byte(pw))
			assert.False(t, s.IsWeak(), "expected %q to be strong (score %d)", pw, s.Score)
			assert.GreaterOrEqual(t, s.Score, ScoreThreshold)
		})
	}
}

func TestScorePassphrase_Empty(t *testing.T) {
	s := ScorePassphrase(nil)
	assert.Equal(t, 0, s.Score)
	assert.True(t, s.IsWeak())
	assert.Equal(t, "instant", s.CrackDisplay)
}

func TestStrengthLabels(t *testing.T) {
	cases := map[int]string{
		0: "weak",
		1: "weak",
		2: "fair",
		3: "strong",
		4: "very strong",
	}
	for score, want := range cases {
		got := Strength{Score: score}.Label()
		assert.Equal(t, want, got, "score %d", score)
	}
}
