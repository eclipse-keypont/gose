// SPDX-FileCopyrightText: 2026 Thales Group and the gose Contributors
// SPDX-License-Identifier: MIT

package gose

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/eclipse-keypont/gose/jose"
)

func TestNewJwtSigner(t *testing.T) {
	// Setup
	mockedKey := MockedSigner{}
	// Act and Assert
	assert.NotNil(t, NewJwtSigner("issuer", &mockedKey))
}

func TestJwtSignerImpl_Sign(t *testing.T) {
	// Setup
	expectedSignature := []byte{1, 2, 3, 4}
	mockedKey := MockedSigner{}
	mockedKey.On("Kid").Return("keyid")
	mockedKey.On("Algorithm").Return(jose.AlgPS256)
	mockedKey.On("Sign", jose.KeyOpsSign, mock.AnythingOfType("[]uint8")).Return(expectedSignature, nil)
	signer := NewJwtSigner("issuer", &mockedKey)
	claims := jose.SettableJwtClaims{
		Audiences: jose.Audiences{Aud: []string{"audience"}},
		Subject:   "subject",
	}
	untyped := map[string]interface{}{
		"name": "John Doe",
	}

	// Act
	jwt, err := signer.Sign(&claims, untyped)

	// Assert
	require.NotEmpty(t, jwt)
	assert.NoError(t, err)

	parts := strings.Split(jwt, ".")
	require.Len(t, parts, 3)

	// header verification
	var header jose.JwsHeader
	require.NoError(t, err)
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	require.NoError(t, err)
	err = json.Unmarshal(headerBytes, &header)
	assert.NoError(t, err)
	assert.Equal(t, jose.AlgPS256, header.Alg)
	assert.Equal(t, jose.JwtType, header.Typ)
	assert.Equal(t, "keyid", header.Kid)
	assert.Empty(t, header.Crit)

	// MarshalBody verification
	var recoveredClaims jose.JwtClaims
	claimsBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	require.NoError(t, err)
	err = json.Unmarshal(claimsBytes, &recoveredClaims)
	require.NoError(t, err)
	assert.Equal(t, claims.Audiences, recoveredClaims.Audiences)
	assert.Equal(t, "issuer", recoveredClaims.Issuer)
	assert.Equal(t, claims.Subject, recoveredClaims.Subject)
	assert.Len(t, recoveredClaims.UntypedClaims, 1)
	var name string
	err = recoveredClaims.UnmarshalCustomClaim("name", &name)
	require.NoError(t, err)
	assert.Equal(t, "John Doe", name)

	// Signature check
	rawSignature, err := base64.RawURLEncoding.DecodeString(parts[2])
	require.NoError(t, err)
	assert.Equal(t, expectedSignature, rawSignature)
}

func TestJwtSignerImpl_Sign_FailsWhenSigningFails(t *testing.T) {
	// Setup
	expectedError := errors.New("Expected")
	mockedKey := MockedSigner{}
	mockedKey.On("Kid").Return("keyid")
	mockedKey.On("Algorithm").Return(jose.AlgPS256)
	mockedKey.On("Sign", jose.KeyOpsSign, mock.AnythingOfType("[]uint8")).Return(nil, expectedError)
	signer := NewJwtSigner("issuer", &mockedKey)
	claims := jose.SettableJwtClaims{
		Audiences: jose.Audiences{Aud: []string{"audience"}},
		Subject:   "subject",
	}

	// Act
	jwt, err := signer.Sign(&claims, nil)

	// Assert
	require.Empty(t, jwt)
	assert.Equal(t, err, expectedError)
}
