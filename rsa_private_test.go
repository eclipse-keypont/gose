// SPDX-FileCopyrightText: 2026 Thales Group and the gose Contributors
// SPDX-License-Identifier: MIT

package gose

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/eclipse-keypont/gose/jose"
)

func TestRsaPrivateKey_MarshalSucceeds(t *testing.T) {
	// Setup
	k, err := rsa.GenerateKey(rand.Reader, 2048)
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
	unmarshalledJwk, err := LoadJwk(bytes.NewReader([]byte(marshalled)), nil)
	require.NoError(t, err)
	require.Equal(t, jwk.Alg(), unmarshalledJwk.Alg())
	require.Equal(t, jwk.Ops(), unmarshalledJwk.Ops())
	require.Equal(t, jwk.Kty(), unmarshalledJwk.Kty())
	require.Equal(t, jwk.Kid(), unmarshalledJwk.Kid())
}

func TestRsaPrivateKey_MarshalPemSucceeds(t *testing.T) {
	// Setup
	k, err := rsa.GenerateKey(rand.Reader, 2048)
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
	require.Equal(t, block.Type, rsaPrivateKeyPemType)
	recoveredKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	require.NoError(t, err)
	assert.Equal(t, recoveredKey.E, k.E)
	assert.Equal(t, recoveredKey.N.Cmp(k.N), 0)
	assert.Equal(t, recoveredKey.D.Cmp(k.D), 0)
	assert.Equal(t, recoveredKey.N.Cmp(k.N), 0)
}

func TestRsaPrivateKey_Verifier(t *testing.T) {
	// Setup
	k, err := rsa.GenerateKey(rand.Reader, 2048)
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
