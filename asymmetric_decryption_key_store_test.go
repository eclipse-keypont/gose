// SPDX-FileCopyrightText: 2026 Thales Group and the gose Contributors
// SPDX-License-Identifier: MIT

package gose

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/eclipse-keypont/gose/jose"
)

func TestAsymmetricDecryptionKeyStoreImpl_Get(t *testing.T) {
	generator := &RsaKeyDecryptionKeyGenerator{}
	key, err := generator.Generate(jose.AlgRSAOAEP, 2048, []jose.KeyOps{jose.KeyOpsDecrypt})
	require.NoError(t, err)
	store, err := NewAsymmetricDecryptionKeyStoreImpl(map[string]AsymmetricDecryptionKey{
		"test": key,
	})
	require.NoError(t, err)
	// Look for key with matching kid
	first, err := store.Get("test")
	assert.NoError(t, err)
	assert.NotNil(t, first)
	// Look without kid. There's only 1 key so we expect that to be returned.
	second, err := store.Get("unknown")
	assert.NoError(t, err)
	assert.NotNil(t, second)
	// Test that we never return a key if kids do not match and we have multiple keys in the store
	store, err = NewAsymmetricDecryptionKeyStoreImpl(map[string]AsymmetricDecryptionKey{
		"test":    key,
		"another": key,
	})
	require.NoError(t, err)
	third, err := store.Get("unknown")
	assert.Error(t, err)
	assert.Nil(t, third)
}
