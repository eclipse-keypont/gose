// SPDX-FileCopyrightText: 2026 Thales Group and the gose Contributors
// SPDX-License-Identifier: MIT

package gose

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/eclipse-keypont/gose/jose"
)

func TestNewVerifierSucceeds(t *testing.T) {
	// Setup
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	jwk, err := JwkFromPublicKey(rsaKey.Public(), []jose.KeyOps{jose.KeyOpsVerify}, nil)
	require.NoError(t, err)

	cases := []jose.Alg{
		jose.AlgPS256,
		jose.AlgRS256,
	}

	// Act
	for _, test := range cases {
		jwk.SetAlg(test)
		k, err := NewVerificationKey(jwk)

		// Assert
		require.Nil(t, err)
		require.NotNil(t, k)
		require.NotEmpty(t, k.Kid())
		require.Equal(t, test, jwk.Alg())
	}
}

func TestNewVerifierFailsWithInvalidOps(t *testing.T) {
	// Setup
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	testCase := [][]jose.KeyOps{
		{jose.KeyOpsSign},
	}
	for _, test := range testCase {
		jwk, err := JwkFromPublicKey(rsaKey.Public(), test, nil)
		require.NoError(t, err)

		// Act
		k, err := NewVerificationKey(jwk)

		// Assert
		assert.Nil(t, k)
		assert.Equal(t, ErrInvalidOperations, err)
	}
}

func TestNewVerifierFailsWhenNotAVerfierKey(t *testing.T) {
	// Setup
	var jwk jose.PrivateRsaKey
	jwk.SetAlg(jose.AlgPS256)
	jwk.SetOps([]jose.KeyOps{jose.KeyOpsSign})

	// Act
	k, err := NewVerificationKey(&jwk)

	// Assert
	require.Equal(t, ErrInvalidOperations, err)
	require.Nil(t, k)
}
