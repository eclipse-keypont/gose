// SPDX-FileCopyrightText: 2026 Thales Group and the gose Contributors
// SPDX-License-Identifier: MIT

package gose

import (
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/eclipse-keypont/gose/jose"
)

var (
	fakeKeyMaterial = []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	fakeNonce       = []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	fakeTag         = []byte{0x70, 0x7d, 0xcf, 0x80, 0xa1, 0xb9, 0xa6, 0x17, 0x03, 0xe7, 0x95, 0xd4, 0xd1, 0x09, 0xf0, 0xfd}
	fakePlaintext   = []byte{0x01}
	fakeCiphertext  = []byte{0xcf}
)

func TestNewAesGcmCryptor_InvalidOps(t *testing.T) {
	key := &jose.OctSecretKey{}
	key.SetAlg(jose.AlgA256GCM)
	key.SetOps([]jose.KeyOps{jose.KeyOpsEncrypt})
	cryptor, err := NewAesGcmCryptorFromJwk(key, []jose.KeyOps{jose.KeyOpsDecrypt})
	assert.Nil(t, cryptor)
	assert.Equal(t, err, ErrInvalidOperations)
}

func TestNewAesGcmCryptor_InvalidKey(t *testing.T) {
	key := &jose.OctSecretKey{}
	key.SetAlg(jose.AlgES256)
	key.SetOps([]jose.KeyOps{jose.KeyOpsEncrypt, jose.KeyOpsDecrypt})
	cryptor, err := NewAesGcmCryptorFromJwk(key, []jose.KeyOps{jose.KeyOpsDecrypt})
	assert.Nil(t, cryptor)
	assert.Equal(t, err, ErrInvalidKeyType)
}

func TestNewAesGcmCryptor(t *testing.T) {
	key := &jose.OctSecretKey{}
	key.SetAlg(jose.AlgA256GCM)
	key.SetOps([]jose.KeyOps{jose.KeyOpsEncrypt, jose.KeyOpsDecrypt})
	key.SetKid("something-unique")
	key.K.SetBytes(fakeKeyMaterial)
	cryptor, err := NewAesGcmCryptorFromJwk(key, []jose.KeyOps{jose.KeyOpsDecrypt})
	assert.NotNil(t, cryptor)
	assert.NoError(t, err)
}

func TestAesGcmCryptor_GenerateNonce(t *testing.T) {
	key := &jose.OctSecretKey{}
	key.SetAlg(jose.AlgA256GCM)
	key.SetOps([]jose.KeyOps{jose.KeyOpsEncrypt, jose.KeyOpsDecrypt})
	key.SetKid("something-unique")
	key.K.SetBytes(fakeKeyMaterial)
	cryptor, err := NewAesGcmCryptorFromJwk(key, []jose.KeyOps{jose.KeyOpsDecrypt})
	require.NotNil(t, cryptor)
	require.NoError(t, err)

	nonce, err := cryptor.GenerateNonce()
	require.NoError(t, err)
	assert.Len(t, nonce, 12)
}

func TestAesGcmCryptor_Getters(t *testing.T) {
	key := &jose.OctSecretKey{}
	key.SetAlg(jose.AlgA256GCM)
	key.SetOps([]jose.KeyOps{jose.KeyOpsEncrypt, jose.KeyOpsDecrypt})
	key.SetKid("something-unique")
	key.K.SetBytes(fakeKeyMaterial)
	cryptor, err := NewAesGcmCryptorFromJwk(key, []jose.KeyOps{jose.KeyOpsDecrypt})
	require.NotNil(t, cryptor)
	require.NoError(t, err)

	assert.Equal(t, cryptor.Kid(), "something-unique")
	assert.Equal(t, cryptor.Algorithm(), jose.AlgA256GCM)
}

func TestAesGcmCryptor_Seal_InvalidOps(t *testing.T) {
	key := &jose.OctSecretKey{}
	key.SetAlg(jose.AlgA256GCM)
	key.SetOps([]jose.KeyOps{jose.KeyOpsDecrypt})
	key.SetKid("something-unique")
	key.K.SetBytes(fakeKeyMaterial)
	cryptor, err := NewAesGcmCryptorFromJwk(key, []jose.KeyOps{jose.KeyOpsDecrypt})
	require.NotNil(t, cryptor)
	require.NoError(t, err)

	ciphertext, tag, err := cryptor.Seal(jose.KeyOpsEncrypt, fakeNonce, fakePlaintext, nil)
	assert.Nil(t, ciphertext)
	assert.Nil(t, tag)
	assert.Equal(t, err, ErrInvalidOperations)
}

func TestAesGcmCryptor_Seal(t *testing.T) {
	key := &jose.OctSecretKey{}
	key.SetAlg(jose.AlgA256GCM)
	key.SetOps([]jose.KeyOps{jose.KeyOpsEncrypt})
	key.SetKid("something-unique")
	key.K.SetBytes(fakeKeyMaterial)
	cryptor, err := NewAesGcmCryptorFromJwk(key, []jose.KeyOps{jose.KeyOpsEncrypt})
	require.NotNil(t, cryptor)
	require.NoError(t, err)

	ciphertext, tag, err := cryptor.Seal(jose.KeyOpsEncrypt, fakeNonce, fakePlaintext, nil)
	assert.Len(t, ciphertext, 1)
	assert.Len(t, tag, 16)
	assert.NoError(t, err)
}

func TestAesGcmCryptor_Open_InvalidOps(t *testing.T) {
	key := &jose.OctSecretKey{}
	key.SetAlg(jose.AlgA256GCM)
	key.SetOps([]jose.KeyOps{jose.KeyOpsEncrypt})
	key.SetKid("something-unique")
	key.K.SetBytes(fakeKeyMaterial)
	cryptor, err := NewAesGcmCryptorFromJwk(key, []jose.KeyOps{jose.KeyOpsEncrypt})
	require.NotNil(t, cryptor)
	require.NoError(t, err)

	plaintext, err := cryptor.Open(jose.KeyOpsDecrypt, fakeNonce, fakeCiphertext, nil, fakeTag)
	assert.Nil(t, plaintext)
	assert.Equal(t, err, ErrInvalidOperations)
}

func TestAesGcmCryptor_Open(t *testing.T) {
	key := &jose.OctSecretKey{}
	key.SetAlg(jose.AlgA256GCM)
	key.SetOps([]jose.KeyOps{jose.KeyOpsDecrypt})
	key.SetKid("something-unique")
	key.K.SetBytes(fakeKeyMaterial)
	cryptor, err := NewAesGcmCryptorFromJwk(key, []jose.KeyOps{jose.KeyOpsDecrypt})
	require.NotNil(t, cryptor)
	require.NoError(t, err)

	plaintext, err := cryptor.Open(jose.KeyOpsDecrypt, fakeNonce, fakeCiphertext, nil, fakeTag)
	assert.Equal(t, plaintext, fakePlaintext)
	assert.NoError(t, err)
}

func TestAesGcmCryptor_RoundTrip(t *testing.T) {
	key := &jose.OctSecretKey{}
	key.SetAlg(jose.AlgA256GCM)
	key.SetOps([]jose.KeyOps{jose.KeyOpsEncrypt, jose.KeyOpsDecrypt})
	key.SetKid("something-unique")
	key.K.SetBytes(fakeKeyMaterial)
	cryptor, err := NewAesGcmCryptorFromJwk(key, []jose.KeyOps{jose.KeyOpsDecrypt, jose.KeyOpsEncrypt})
	require.NotNil(t, cryptor)
	require.NoError(t, err)

	for i := 0; i < 50; i++ {
		toSeal := make([]byte, 374)
		_, err = rand.Read(toSeal)
		require.Nil(t, err)
		nonce, err := cryptor.GenerateNonce()
		require.NoError(t, err)
		ciphertext, tag, err := cryptor.Seal(jose.KeyOpsEncrypt, nonce, toSeal, nil)
		require.Nil(t, err)
		plaintext, err := cryptor.Open(jose.KeyOpsDecrypt, nonce, ciphertext, nil, tag)
		assert.NoError(t, err)
		assert.Equal(t, plaintext, toSeal)
	}
}
