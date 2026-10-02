// SPDX-FileCopyrightText: 2026 Thales Group and the gose Contributors
// SPDX-License-Identifier: MIT

package gose

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"log"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/eclipse-keypont/gose/jose"
)

const jwkRSAOAEPEncryptionRaw = `
{
	"kty":"RSA",
	"kid": "1",
    "key_ops": ["encrypt"],
	"alg": "RSA-OAEP",
	"n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
	"e":"AQAB"
}`

func generateEncryptor(t *testing.T) *JweRsaKeyEncryptionEncryptorImpl {
	b := make([]byte, 16)
	random := rand.Reader
	res, _ := random.Read(b)
	log.Print(res)

	buf := bytes.NewReader([]byte(jwkRSAOAEPEncryptionRaw))
	jwkRSAOAEPEncryption, err := LoadJwk(buf, nil)
	require.NoError(t, err)

	rsaOAEPEncryptor, err := NewJweRsaKeyEncryptionEncryptorImpl(jwkRSAOAEPEncryption, rand.Reader)
	require.NoError(t, err)

	return rsaOAEPEncryptor
}

func TestNewJweRsaKeyEncryptionEncryptorImpl(t *testing.T) {
	rsaOAEPEncryptor := generateEncryptor(t)

	assert.Equal(t, jose.AlgRSAOAEP, rsaOAEPEncryptor.rsaAlg)
	assert.Equal(t, "1", rsaOAEPEncryptor.rsaPublicKid)
	assert.NotNil(t, rsaOAEPEncryptor.rsaPublicKey)
	assert.NotNil(t, rsaOAEPEncryptor.randomSource)
}

func TestNewJweRsaKeyEncryptionEncryptorImpl_InvalidJwk(t *testing.T) {
	generator := &ECDSASigningKeyGenerator{}
	k, err := generator.Generate(jose.AlgES256, []jose.KeyOps{jose.KeyOpsSign, jose.KeyOpsDecrypt})
	require.NoError(t, err)
	verifier, err := k.Verifier()
	require.NoError(t, err)
	jwk, err := verifier.Jwk()
	require.NoError(t, err)
	_, err = NewJweRsaKeyEncryptionEncryptorImpl(jwk, rand.Reader)
	assert.Equal(t, ErrInvalidKeyType, err)
}

// Encrypting with SHA-1 must advertise "RSA-OAEP", the RFC 7518 §4.3 name for that variant.
func TestRSAOAEPJWEEncrypt_Sha1LabelsRsaOaep(t *testing.T) {
	rsaOAEPEncryptor := generateEncryptor(t)
	jwe, err := rsaOAEPEncryptor.Encrypt([]byte("plaintext"), crypto.SHA1)
	require.NoError(t, err)

	protectedHeader := decodeProtectedHeader(t, jwe)
	assert.Equal(t, jose.AlgRSAOAEPSHA1, protectedHeader.Alg)
	assert.Equal(t, jose.Alg("RSA-OAEP"), protectedHeader.Alg)
}

// RFC 7518 §4.3 registers OAEP algorithms for SHA-1 and SHA-256 only. Wrapping with any
// other digest would produce a JWE that no "alg" value describes, so it must be refused
// rather than silently mislabelled.
func TestRSAOAEPJWEEncrypt_UnregisteredDigestRejected(t *testing.T) {
	rsaOAEPEncryptor := generateEncryptor(t)
	for _, hash := range []crypto.Hash{crypto.SHA384, crypto.SHA512, crypto.Hash(0)} {
		_, err := rsaOAEPEncryptor.Encrypt([]byte("plaintext"), hash)
		assert.ErrorIs(t, err, ErrInvalidAlgorithm, "digest %v", hash)
	}
}

// A key whose alg names a signing algorithm is not usable for OAEP key wrapping.
func TestNewJweRsaKeyEncryptionEncryptorImpl_NonOaepRsaKeyRejected(t *testing.T) {
	raw := strings.Replace(jwkRSAOAEPEncryptionRaw, `"alg": "RSA-OAEP"`, `"alg": "RS256"`, 1)
	jwk, err := LoadJwk(bytes.NewReader([]byte(raw)), nil)
	require.NoError(t, err)
	_, err = NewJweRsaKeyEncryptionEncryptorImpl(jwk, rand.Reader)
	assert.ErrorIs(t, err, ErrInvalidAlgorithm)
}

func decodeProtectedHeader(t *testing.T, jwe string) jose.JweProtectedHeader {
	t.Helper()
	raw, err := base64.RawURLEncoding.DecodeString(strings.Split(jwe, ".")[0])
	require.NoError(t, err)
	var protectedHeader jose.JweProtectedHeader
	require.NoError(t, json.Unmarshal(raw, &protectedHeader))
	return protectedHeader
}

func TestRSAOAEPJWEEncrypt(t *testing.T) {
	rsaOAEPEncryptor := generateEncryptor(t)
	jwe, err := rsaOAEPEncryptor.Encrypt([]byte("plaintext"), crypto.SHA256)
	require.NoError(t, err)
	require.NotEmpty(t, jwe)

	// verify structure
	splits := strings.Split(jwe, ".")
	require.Equal(t, 5, len(splits))

	// protected header
	require.NotEmpty(t, splits[0])
	protectedHeaderRaw, err := base64.RawURLEncoding.DecodeString(splits[0])
	require.NoError(t, err)
	var protectedHeader jose.JweProtectedHeader
	err = json.Unmarshal(protectedHeaderRaw, &protectedHeader)
	require.NoError(t, err)
	// Encrypting with SHA-256 must advertise RFC 7518 §4.3 "RSA-OAEP-256", not "RSA-OAEP",
	// which denotes the SHA-1 variant.
	assert.Equal(t, jose.AlgRSAOAEPSHA2, protectedHeader.Alg)
	assert.Equal(t, "1", protectedHeader.Kid)
	assert.Equal(t, jose.EncA256GCM, protectedHeader.Enc)

	// encrypted CEK
	require.NotEmpty(t, splits[0])

	// iv
	encodedIV := splits[2]
	require.NotEmpty(t, encodedIV)
	iv, err := base64.RawURLEncoding.DecodeString(encodedIV)
	require.NoError(t, err)
	assert.Equal(t, 12, len(iv))

	// ciphertext
	require.NotEmpty(t, splits[3])

	// tag
	require.NotEmpty(t, splits[4])
}
