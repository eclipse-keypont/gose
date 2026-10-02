// SPDX-FileCopyrightText: 2026 Thales Group and the gose Contributors
// SPDX-License-Identifier: MIT

package gose

import (
	"crypto/sha256"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestHmacShaCryptor(t *testing.T) {
	kid := "hmac-0"
	cryptor := NewHmacShaCryptor(kid, sha256.New())
	t.Run("testHmacKid", func(t *testing.T) {
		testHmacKid(t, cryptor, kid)
	})
	t.Run("testHmacHash", func(t *testing.T) {
		testHmacHash(t, cryptor, []byte("hashme"))
	})
}

func testHmacKid(t *testing.T, cryptor HmacKey, kid string) {
	require.Equal(t, kid, cryptor.Kid())
}

func testHmacHash(t *testing.T, cryptor HmacKey, input []byte) {
	sha := cryptor.Hash(input)
	require.NotEmpty(t, sha)
	require.Equal(t, 32, len(sha))
	require.NotContains(t, string(sha), string(input))
}
