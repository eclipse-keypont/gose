// SPDX-FileCopyrightText: 2026 Thales Group and the gose Contributors
// SPDX-License-Identifier: MIT

package gose

import (
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/eclipse-keypont/gose/jose"
)

func TestAesCbcCryptor(t *testing.T) {
	var err error
	iv := make([]byte, 16)
	_, err = rand.Read(iv)
	require.NoError(t, err)

	expectedKid := "aes0"
	expectedAlg := jose.AlgA256CBC

	// mocking the block mode cipher
	mc1 := &MockBlockMode{}
	mc1.On("BlockSize").Return(len(iv))
	require.NoError(t, err)
	c1 := NewAesCbcCryptor(mc1, expectedKid, expectedAlg)

	t.Run("testKid", func(t *testing.T) {
		testKid(t, expectedKid, c1)
	})

	t.Run("testAlgorithm", func(t *testing.T) {
		testAlgorithm(t, expectedAlg, c1)
	})

	t.Run("testSeal", func(t *testing.T) {
		// mocking the block mode cipher for encryption
		mc2 := &MockBlockMode{
			mode: ModeEncrypt,
		}
		mc2.On("BlockSize").Return(len(iv))
		require.NoError(t, err)
		c2 := NewAesCbcCryptor(mc2, expectedKid, expectedAlg)
		testSeal(t, c2)
	})

	t.Run("testOpen", func(t *testing.T) {
		// mocking the block mode cipher for decryption
		mc3 := &MockBlockMode{
			mode: ModeDecrypt,
		}
		mc3.On("BlockSize").Return(len(iv))
		require.NoError(t, err)
		c3 := NewAesCbcCryptor(mc3, expectedKid, expectedAlg)
		testOpen(t, c3)
	})
}

func testKid(t *testing.T, expectedKid string, cryptor BlockEncryptionKey) {
	kid := cryptor.Kid()
	require.Equal(t, expectedKid, kid)
}

func testAlgorithm(t *testing.T, expectedAlg jose.Alg, cryptor BlockEncryptionKey) {
	alg := cryptor.Algorithm()
	require.Equal(t, expectedAlg, alg)
}

func testSeal(t *testing.T, cryptor BlockEncryptionKey) {
	small := []byte("ping")
	cSmall := cryptor.Seal(small)
	require.Equal(t, 0, len(cSmall)%16)
	require.NotEqual(t, small, cSmall)
	require.Contains(t, string(cSmall), mockExpectedCiphertext)

	big := []byte("pingpingpingpingpingpingpingpingpingping")
	cBig := cryptor.Seal(big)
	require.Equal(t, 0, len(cBig)%16)
	require.NotEqual(t, big, cBig)
	require.Contains(t, string(cBig), mockExpectedCiphertext)
}

func testOpen(t *testing.T, cryptor BlockEncryptionKey) {
	small := []byte("ping")
	cSmall := cryptor.Open(small)
	require.Equal(t, 0, len(cSmall)%16)
	require.NotEqual(t, small, cSmall)
	require.Contains(t, string(cSmall), mockExpectedCleartext)

	big := []byte("pingpingpingpingpingpingpingpingpingping")
	cBig := cryptor.Open(big)
	require.Equal(t, 0, len(cBig)%16)
	require.NotEqual(t, big, cBig)
	require.Contains(t, string(cBig), mockExpectedCleartext)
}
