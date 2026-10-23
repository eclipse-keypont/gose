// SPDX-FileCopyrightText: 2026 Thales Group and the gose Contributors
// SPDX-License-Identifier: MIT

package gose

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/eclipse-keypont/gose/jose"
)

// An oct key's length must match the AEAD alg it is labelled with, so loading cannot
// silently drop to a weaker AES key size than the alg advertises.
func TestLoadSymmetricAEAD_RejectsKeyLengthMismatch(t *testing.T) {
	var short jose.OctSecretKey
	short.SetAlg(jose.AlgA256GCM)
	short.SetOps([]jose.KeyOps{jose.KeyOpsEncrypt, jose.KeyOpsDecrypt})
	short.K.SetBytes(make([]byte, 16)) // 128-bit key under an A256GCM label

	_, err := LoadSymmetricAEAD(&short, nil)
	require.ErrorIs(t, err, ErrInvalidKeyLength)

	var good jose.OctSecretKey
	good.SetAlg(jose.AlgA256GCM)
	good.SetOps([]jose.KeyOps{jose.KeyOpsEncrypt, jose.KeyOpsDecrypt})
	good.K.SetBytes(make([]byte, 32))

	_, err = LoadSymmetricAEAD(&good, nil)
	require.NoError(t, err)
}
