// SPDX-FileCopyrightText: 2026 Thales Group and the gose Contributors
// SPDX-License-Identifier: MIT

package gose

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/eclipse-keypont/gose/jose"
)

func TestNewECVerifierSucceeds(t *testing.T) {
	for _, curve := range curves {
		// Setup
		ecdsaKey, err := ecdsa.GenerateKey(curve, rand.Reader)
		require.NoError(t, err)
		jwk, err := JwkFromPublicKey(ecdsaKey.Public(), []jose.KeyOps{jose.KeyOpsVerify}, nil)
		require.NoError(t, err)

		// Act
		k, err := NewVerificationKey(jwk)

		// Assert
		require.Nil(t, err)
		require.NotNil(t, k)
		require.NotEmpty(t, k.Kid())
	}
}

func TestNewECVerifierFailsWithInvalidOps(t *testing.T) {
	for _, curve := range curves {
		// Setup
		ecdsaKey, err := ecdsa.GenerateKey(curve, rand.Reader)
		require.NoError(t, err)

		testCase := [][]jose.KeyOps{
			{jose.KeyOpsSign},
		}
		for _, test := range testCase {
			jwk, err := JwkFromPublicKey(ecdsaKey.Public(), test, nil)
			require.NoError(t, err)

			// Act
			k, err := NewVerificationKey(jwk)

			// Assert
			assert.Nil(t, k)
			assert.Equal(t, ErrInvalidOperations, err)
		}
	}
}

func TestNewECVerifierMarshalSucceeds(t *testing.T) {
	for _, curve := range curves {
		// Setup
		require.NotNil(t, rand.Reader)
		ecdsaKey, err := ecdsa.GenerateKey(curve, rand.Reader)
		require.NoError(t, err)
		jwk, err := JwkFromPublicKey(ecdsaKey.Public(), []jose.KeyOps{jose.KeyOpsVerify}, nil)
		require.NoError(t, err)
		k, err := NewVerificationKey(jwk)
		require.NoError(t, err)

		// Act
		str, err := k.Marshal()

		// Assert
		require.NoError(t, err)
		require.NotEmpty(t, str)
		buf := bytes.NewReader([]byte(str))
		jwkOut, err := LoadJwk(buf, nil)
		require.NoError(t, err)
		require.Equal(t, jwk.Kid(), jwkOut.Kid())
		require.Equal(t, jwk.Kty(), jwkOut.Kty())
		require.Equal(t, jwk.Alg(), jwkOut.Alg())
		require.Equal(t, jwk.Ops(), jwkOut.Ops())

		goodEcJwk := jwk.(*jose.PublicEcKey)
		marshalledECJwk := jwkOut.(*jose.PublicEcKey)
		require.Equal(t, 0, goodEcJwk.X.Int().Cmp(marshalledECJwk.X.Int()))
		require.Equal(t, 0, goodEcJwk.Y.Int().Cmp(marshalledECJwk.Y.Int()))
	}
}

func TestNewECVerifierMarshalPemSucceeds(t *testing.T) {
	for _, curve := range curves {
		// Setup
		ecdsaKey, err := ecdsa.GenerateKey(curve, rand.Reader)
		require.NoError(t, err)
		jwk, err := JwkFromPublicKey(ecdsaKey.Public(), []jose.KeyOps{jose.KeyOpsVerify}, nil)
		require.NoError(t, err)
		k, err := NewVerificationKey(jwk)
		require.NoError(t, err)

		// Act
		str, err := k.MarshalPem()

		// Assert
		require.NoError(t, err)
		require.NotEmpty(t, str)
		block, overflow := pem.Decode([]byte(str))
		require.Empty(t, overflow)
		require.Equal(t, block.Type, ecPublicKeyPemType)
		recoveredKey, err := x509.ParsePKIXPublicKey(block.Bytes)
		require.NoError(t, err)
		recoveredECKey, ok := recoveredKey.(*ecdsa.PublicKey)
		require.True(t, ok)
		assert.Equal(t, recoveredECKey.X, ecdsaKey.X)
		assert.Equal(t, recoveredECKey.Y, ecdsaKey.Y)
	}
}

func TestNewECVerifierFailsWhenNotAVerfierKey(t *testing.T) {
	// Setup
	var jwk jose.PrivateEcKey
	jwk.SetAlg(jose.AlgES256)
	jwk.SetOps([]jose.KeyOps{jose.KeyOpsSign})
	jwk.SetUse(jose.KeyUseSig)
	jwk.X.SetBytes([]byte("ABCDEFGHIJKLMNOPQRSTUVWXYZ"))
	jwk.Y.SetBytes([]byte("AABABB"))
	jwk.D.SetBytes([]byte("AABABB"))

	// Act
	k, err := NewVerificationKey(&jwk)

	// Assert
	require.Equal(t, ErrInvalidOperations, err)
	require.Nil(t, k)
}
