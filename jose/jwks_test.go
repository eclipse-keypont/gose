// SPDX-FileCopyrightText: 2026 Thales Group and the gose Contributors
// SPDX-License-Identifier: MIT

package jose

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestJwks_UnmarshalJSON(t *testing.T) {
	// Setup
	const input = `{
	"keys": [ 
	{
		"kty": "RSA",
		"n": "BBBB",
		"e": "AQAB",
		"kid": "1"
	},
	{
		"kty": "RSA",
		"n": "BBBB",
		"e": "AQAB",
		"kid": "2"
	}]
}
`
	var jwks Jwks

	// Act
	err := json.Unmarshal([]byte(input), &jwks)

	// Assert

	assert.NoError(t, err)
	require.Len(t, jwks.Keys, 2)
	assert.Equal(t, "1", jwks.Keys[0].Kid())
	assert.Equal(t, "2", jwks.Keys[1].Kid())
}

func TestJwks_MarshalJSON(t *testing.T) {
	// Setup
	var rsa PrivateRsaKey
	rsa.SetKid("1")
	rsa.N.SetBytes([]byte{0, 1, 2, 3, 4})
	rsa.D.SetBytes([]byte{0, 1, 2, 3, 4})
	rsa.P.SetBytes([]byte{0, 1, 2, 3, 4})
	rsa.Q.SetBytes([]byte{0, 1, 2, 3, 4})
	rsa.Dp.SetBytes([]byte{0, 1, 2, 3, 4})
	rsa.Dq.SetBytes([]byte{0, 1, 2, 3, 4})
	rsa.Qi.SetBytes([]byte{0, 1, 2, 3, 4})
	rsa.E.SetBytes([]byte{1, 0, 1})

	jwks := Jwks{
		Keys: []Jwk{
			&rsa,
			&rsa,
		},
	}

	// Act
	marshalled, err := json.Marshal(&jwks)

	// Assert
	assert.NoError(t, err)
	assert.NotEmpty(t, marshalled)
}
