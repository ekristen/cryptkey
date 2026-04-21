package common

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestVersion(t *testing.T) {
	assert.Equal(t, "cryptkey", NAME)
	assert.Equal(t, "v1.0.0", SUMMARY)
}
