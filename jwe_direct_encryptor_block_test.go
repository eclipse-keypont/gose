// SPDX-FileCopyrightText: 2026 Thales Group and the gose Contributors
// SPDX-License-Identifier: MIT

package gose

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/eclipse-keypont/gose/jose"
)

func TestJweDirectEncryptorBlock(t *testing.T) {
	// vars
	blockSize := 16
	iv := make([]byte, blockSize)
	_, err := rand.Read(iv)
	require.NoError(t, err)
	require.NotEmpty(t, iv)
	expectedAesKid := "aes0"
	expectedHmacKid := "hmac0"
	expectedAlg := jose.AlgA256CBC

	// mocking the block mode cipher for encryption
	mcEnc := &MockBlockMode{
		mode: ModeEncrypt,
	}
	bekEnc := NewAesCbcCryptor(mcEnc, expectedAesKid, expectedAlg)
	hk := NewHmacShaCryptor(expectedHmacKid, sha256.New())
	encryptor := NewJweDirectEncryptorBlock(bekEnc, hk, iv)
	mcEnc.On("BlockSize").Return(len(iv))

	// mocking the block mode cipher for decryption
	mcDec := &MockBlockMode{
		mode: ModeDecrypt,
	}
	mcDec.On("BlockSize").Return(len(iv))
	require.NoError(t, err)
	bekDec := NewAesCbcCryptor(mcDec, expectedAesKid, expectedAlg)
	decryptor := NewJweDirectDecryptorBlock(bekDec, hk)

	// running tests
	t.Run("testEncryptDecrypt", func(t *testing.T) {
		testEncryptDecrypt(t, encryptor, decryptor, iv)
	})
}

func testEncryptDecrypt(t *testing.T, cryptor *JweDirectEncryptorBlock, decryptor *JweDirectDecryptorBlock, expectedIV []byte) {
	// **********
	// ENCRYPTION
	// **********
	marshalledJwe, err := cryptor.Encrypt([]byte(mockExpectedCleartext), nil)
	require.NoError(t, err)
	require.NotEmpty(t, marshalledJwe)

	// verify the structure
	splits := strings.Split(marshalledJwe, ".")
	require.Equal(t, 5, len(splits))

	// For direct encryption, the encrypted key is nil
	// we expected an empty string for the second part of the JWE
	require.Empty(t, splits[1])

	// other parts should not be empty
	require.NotEmpty(t, splits[0])
	require.NotEmpty(t, splits[2])
	require.NotEmpty(t, splits[3])
	require.NotEmpty(t, splits[4])

	// verify IV
	iv, err := base64.RawURLEncoding.DecodeString(splits[2])
	require.NoError(t, err)
	require.Equal(t, expectedIV, iv)

	// verify ciphertext
	ciphertext, err := base64.RawURLEncoding.DecodeString(splits[3])
	require.NoError(t, err)
	require.Contains(t, string(ciphertext), mockExpectedCiphertext)

	// **********
	// DECRYPTION
	// **********
	plaintext, _, err := decryptor.Decrypt(marshalledJwe)
	require.NoError(t, err)

	// decryption
	require.NotEmpty(t, plaintext)
	require.Equal(t, mockExpectedCleartext, string(plaintext))
}
