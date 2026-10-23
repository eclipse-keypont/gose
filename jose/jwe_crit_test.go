// SPDX-FileCopyrightText: 2026 Thales Group and the gose Contributors
// SPDX-License-Identifier: MIT

package jose

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// RFC 7516 §4.1.13: a JWE naming a critical extension the recipient does not understand
// must be rejected. gose implements no JWE extensions, so any non-empty "crit" is fatal,
// matching jwt.Verify's handling for JWS.
func TestJweCompactUnmarshalRejectsCritHeader(t *testing.T) {
	var jwe JweRfc7516Compact
	err := jwe.Unmarshal(compactJwe(`{"alg":"dir","enc":"A256GCM","crit":["x-policy"],"x-policy":"must-understand"}`))
	require.ErrorIs(t, err, ErrCritHeaderNotSupported)
}

func TestJweLegacyUnmarshalRejectsCritHeader(t *testing.T) {
	var jwe Jwe
	err := jwe.Unmarshal(compactJwe(`{"alg":"dir","enc":"A256GCM","crit":["x-policy"],"x-policy":"must-understand"}`))
	require.ErrorIs(t, err, ErrCritHeaderNotSupported)
}

// An empty or absent "crit" must still parse.
func TestJweCompactUnmarshalAcceptsEmptyCrit(t *testing.T) {
	var jwe JweRfc7516Compact
	assert.NoError(t, jwe.Unmarshal(compactJwe(`{"alg":"dir","enc":"A256GCM"}`)))
	var jwe2 JweRfc7516Compact
	assert.NoError(t, jwe2.Unmarshal(compactJwe(`{"alg":"dir","enc":"A256GCM","crit":[]}`)))
}
