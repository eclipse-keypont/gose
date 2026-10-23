// SPDX-FileCopyrightText: 2026 Thales Group and the gose Contributors
// SPDX-License-Identifier: MIT

package gose

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
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

// stubAEAD wraps a real AEAD and overrides Seal, standing in for an AEAD whose Seal
// panics (as a token-backed one does on failure) or returns output of the wrong length.
type stubAEAD struct {
	cipher.AEAD
	seal func(dst, nonce, plaintext, aad []byte) []byte
}

func (s stubAEAD) Seal(dst, nonce, plaintext, aad []byte) []byte {
	return s.seal(dst, nonce, plaintext, aad)
}

func newStubCryptor(t *testing.T, seal func(dst, nonce, plaintext, aad []byte) []byte) AeadEncryptionKey {
	t.Helper()
	block, err := aes.NewCipher(fakeKeyMaterial)
	require.NoError(t, err)
	aead, err := cipher.NewGCM(block)
	require.NoError(t, err)
	cryptor, err := NewAesGcmCryptor(stubAEAD{AEAD: aead, seal: seal}, rand.Reader, "kid", jose.AlgA256GCM, []jose.KeyOps{jose.KeyOpsEncrypt})
	require.NoError(t, err)
	return cryptor
}

func TestAesGcmCryptor_Seal_PanicBecomesError(t *testing.T) {
	tokenErr := errors.New("token failure")
	for name, tc := range map[string]struct {
		value any
		cause error
	}{
		"error":  {value: tokenErr, cause: tokenErr},
		"string": {value: "token failure"},
	} {
		t.Run(name, func(t *testing.T) {
			cryptor := newStubCryptor(t, func(_, _, _, _ []byte) []byte { panic(tc.value) })
			var (
				ciphertext, tag []byte
				err             error
			)
			require.NotPanics(t, func() {
				ciphertext, tag, err = cryptor.Seal(jose.KeyOpsEncrypt, fakeNonce, fakePlaintext, nil)
			})
			assert.ErrorIs(t, err, ErrSealFailed)
			assert.ErrorContains(t, err, "token failure")
			if tc.cause != nil {
				assert.ErrorIs(t, err, tc.cause)
			}
			assert.Nil(t, ciphertext)
			assert.Nil(t, tag)
		})
	}
}

func TestAesGcmCryptor_Seal_NilNonceWithoutAEADSupport(t *testing.T) {
	// The standard library GCM cannot supply a nonce and panics on an empty one.
	key := &jose.OctSecretKey{}
	key.SetAlg(jose.AlgA256GCM)
	key.SetOps([]jose.KeyOps{jose.KeyOpsEncrypt})
	key.K.SetBytes(fakeKeyMaterial)
	cryptor, err := NewAesGcmCryptorFromJwk(key, []jose.KeyOps{jose.KeyOpsEncrypt})
	require.NoError(t, err)

	ciphertext, tag, err := cryptor.Seal(jose.KeyOpsEncrypt, nil, fakePlaintext, nil)
	assert.ErrorIs(t, err, ErrSealFailed)
	assert.Nil(t, ciphertext)
	assert.Nil(t, tag)
}

func TestAesGcmCryptor_Seal_OutputLength(t *testing.T) {
	const tagSize, nonceSize = 16, 12
	for name, tc := range map[string]struct {
		nonce  []byte
		outLen int
		ok     bool
	}{
		"short output":               {nonce: fakeNonce, outLen: len(fakePlaintext) + tagSize - 1},
		"long output":                {nonce: fakeNonce, outLen: len(fakePlaintext) + tagSize + 1},
		"supplied nonce missing":     {nonce: nil, outLen: len(fakePlaintext) + tagSize},
		"supplied nonce appended":    {nonce: nil, outLen: len(fakePlaintext) + tagSize + nonceSize, ok: true},
		"caller nonce, exact output": {nonce: fakeNonce, outLen: len(fakePlaintext) + tagSize, ok: true},
	} {
		t.Run(name, func(t *testing.T) {
			cryptor := newStubCryptor(t, func(dst, _, _, _ []byte) []byte {
				return append(dst, make([]byte, tc.outLen)...)
			})
			ciphertext, tag, err := cryptor.Seal(jose.KeyOpsEncrypt, tc.nonce, fakePlaintext, nil)
			if !tc.ok {
				assert.ErrorIs(t, err, ErrSealFailed)
				assert.Nil(t, ciphertext)
				assert.Nil(t, tag)
				return
			}
			require.NoError(t, err)
			assert.Len(t, ciphertext, len(fakePlaintext))
			assert.Len(t, tag, tc.outLen-len(fakePlaintext))
		})
	}
}
