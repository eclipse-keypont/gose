// SPDX-FileCopyrightText: 2026 Thales Group and the gose Contributors
// SPDX-License-Identifier: MIT

package gose

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

const (
	ModeEncrypt = iota // blockModeCloser is in encrypt mode
	ModeDecrypt        // blockModeCloser is in decrypt mode

)

const (
	mockExpectedCleartext  = "decrypted"
	mockExpectedCiphertext = "encrypted"
)

type MockBlockMode struct {
	mock.Mock
	mode int
}

func (mbm *MockBlockMode) BlockSize() int {
	args := mbm.Called()
	return args.Get(0).(int)
}

// In order to simulate a behavior tangible for tests, i.e encrypt or decrypt according to the mode, we simply return a
// string that inform us if we properly were in the encrypt or decrypt mode
func (mbm *MockBlockMode) CryptBlocks(dst, _ []byte) {
	switch mbm.mode {
	case ModeDecrypt:
		copy(dst, mockExpectedCleartext)
	case ModeEncrypt:

		copy(dst, mockExpectedCiphertext)
	default:
		panic("unexpected mode")
	}
}

func VerifyJWEStructure(t *testing.T, jwe string) {
	require.NotEmpty(t, jwe)
	// verify the structure
	splits := strings.Split(jwe, ".")
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
	require.NotEmpty(t, iv)
}
