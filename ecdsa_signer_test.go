// SPDX-FileCopyrightText: 2026 Thales Group and the gose Contributors
// SPDX-License-Identifier: MIT

package gose

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/eclipse-keypont/gose/jose"
)

var curves = []elliptic.Curve{elliptic.P256(), elliptic.P384(), elliptic.P521()}

func TestNewEcdsaSigningKey_Succeeds(t *testing.T) {
	for _, curve := range curves {
		k, err := ecdsa.GenerateKey(curve, rand.Reader)
		require.NoError(t, err)
		jwk, err := JwkFromPrivateKey(k, []jose.KeyOps{jose.KeyOpsSign}, nil)
		require.NoError(t, err)

		// Act
		signer, err := NewSigningKey(jwk, []jose.KeyOps{jose.KeyOpsSign})

		// Assert
		require.NoError(t, err)
		require.NotNil(t, signer)
	}
}

func TestNewEcdsaSigningKey_FailsWhenInvalidOperations(t *testing.T) {
	for _, curve := range curves {
		// Setup
		k, err := ecdsa.GenerateKey(curve, rand.Reader)
		require.NoError(t, err)
		testCase := [][]jose.KeyOps{
			{jose.KeyOpsVerify},
			{jose.KeyOpsSign, jose.KeyOpsVerify},
		}
		for _, test := range testCase {
			jwk, err := JwkFromPrivateKey(k, []jose.KeyOps{jose.KeyOpsSign}, nil)
			require.NoError(t, err)

			// Act
			signer, err := NewSigningKey(jwk, test)

			// Assert
			require.Nil(t, signer)
			require.Equal(t, ErrInvalidOperations, err)
		}
	}
}

func TestNewEcdsaSigningKey_FailsWhenInvalidJwk(t *testing.T) {
	for _, curve := range curves {
		// Setup
		k, err := ecdsa.GenerateKey(curve, rand.Reader)
		require.NoError(t, err)
		jwk, err := JwkFromPublicKey(k.Public(), []jose.KeyOps{jose.KeyOpsSign}, nil)
		require.NoError(t, err)

		// Act
		signer, err := NewSigningKey(jwk, []jose.KeyOps{jose.KeyOpsSign})

		// Assert
		require.Error(t, err)
		require.Nil(t, signer)
	}
}

func TestNewEcdsaSigningKey_MarshalSucceeds(t *testing.T) {
	for _, curve := range curves {
		// Setup
		k, err := ecdsa.GenerateKey(curve, rand.Reader)
		require.NoError(t, err)
		jwk, err := JwkFromPrivateKey(k, []jose.KeyOps{jose.KeyOpsSign}, nil)
		require.NoError(t, err)
		signer, err := NewSigningKey(jwk, []jose.KeyOps{jose.KeyOpsSign})
		require.NoError(t, err)

		// Act
		marshalled, err := signer.Marshal()

		// Assert
		require.NoError(t, err)
		require.NotNil(t, marshalled)
		payload := bytes.NewReader([]byte(marshalled))
		unmarshalledJwk, err := LoadJwk(payload, nil)
		require.NoError(t, err)
		require.Equal(t, jwk.Alg(), unmarshalledJwk.Alg())
		require.Equal(t, jwk.Ops(), unmarshalledJwk.Ops())
		require.Equal(t, jwk.Kty(), unmarshalledJwk.Kty())
		require.Equal(t, jwk.Kid(), unmarshalledJwk.Kid())
	}
}

func TestNewEcdsaSigningKey_MarshalPemSucceeds(t *testing.T) {
	for _, curve := range curves {
		// Setup
		k, err := ecdsa.GenerateKey(curve, rand.Reader)
		require.NoError(t, err)
		jwk, err := JwkFromPrivateKey(k, []jose.KeyOps{jose.KeyOpsSign}, nil)
		require.NoError(t, err)
		signer, err := NewSigningKey(jwk, []jose.KeyOps{jose.KeyOpsSign})

		require.NoError(t, err)

		// Act
		marshalled, err := signer.MarshalPem()

		// Assert
		require.NoError(t, err)
		require.NotEmpty(t, marshalled)
		block, overflow := pem.Decode([]byte(marshalled))
		require.Empty(t, overflow)
		require.Equal(t, block.Type, ecdsaPrivateKeyPerType)
		recoveredKey, err := x509.ParseECPrivateKey(block.Bytes)
		require.NoError(t, err)
		assert.Equal(t, recoveredKey.D, k.D)
		assert.Equal(t, recoveredKey.X, k.X)
		assert.Equal(t, recoveredKey.Y, k.Y)
	}
}

func TestEcdsaSigningKeyImpl_Verifier(t *testing.T) {
	for _, curve := range curves {
		// Setup
		k, err := ecdsa.GenerateKey(curve, rand.Reader)
		require.NoError(t, err)
		jwk, err := JwkFromPrivateKey(k, []jose.KeyOps{jose.KeyOpsSign}, nil)
		require.NoError(t, err)
		signer, err := NewSigningKey(jwk, []jose.KeyOps{jose.KeyOpsSign})
		require.NoError(t, err)

		// Act
		verifier, err := signer.Verifier()

		// Assert
		assert.NoError(t, err)
		assert.NotNil(t, verifier)
		assert.Equal(t, verifier.Kid(), signer.Kid())

		// Sign something, then verify
		testData := make([]byte, 10)
		_, err = rand.Read(testData)
		require.NoError(t, err)
		signature, err := signer.Sign(jose.KeyOpsSign, testData)
		require.NoError(t, err)
		matches := verifier.Verify(jose.KeyOpsVerify, testData, signature)
		assert.True(t, matches)
	}
}
