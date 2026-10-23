// SPDX-FileCopyrightText: 2026 Thales Group and the gose Contributors
// SPDX-License-Identifier: MIT

package jose

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// The signature segment must be canonical base64url, so a verified JWS has exactly one
// string form. A non-canonical encoding of the same signature bytes must be rejected.
func TestJwsUnmarshal_RejectsNonCanonicalSignature(t *testing.T) {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"x"}`))
	sig := make([]byte, 32)
	canonical := base64.RawURLEncoding.EncodeToString(sig)

	// Canonical form parses.
	var jws Jws
	_, err := jws.Unmarshal(header + "." + payload + "." + canonical)
	require.NoError(t, err)

	// A CR/LF inside the signature segment decodes to the same bytes but is a different
	// string; it must be rejected rather than silently accepted.
	withNewline := header + "." + payload + "." + canonical[:8] + "\r\n" + canonical[8:]
	var jws2 Jws
	_, err = jws2.Unmarshal(withNewline)
	require.ErrorIs(t, err, ErrJwtFormat)

	// Flipping an unused trailing bit of the last character yields the same bytes but a
	// different string; it must also be rejected.
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	last := strings.IndexByte(alphabet, canonical[len(canonical)-1])
	require.GreaterOrEqual(t, last, 0)
	altered := canonical[:len(canonical)-1] + string(alphabet[last^0x1])
	if altered != canonical {
		var jws3 Jws
		_, err = jws3.Unmarshal(header + "." + payload + "." + altered)
		require.ErrorIs(t, err, ErrJwtFormat)
	}
}
