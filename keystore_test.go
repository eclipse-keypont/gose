// SPDX-FileCopyrightText: 2026 Thales Group and the gose Contributors
// SPDX-License-Identifier: MIT

package gose

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/eclipse-keypont/gose/jose"
)

func BenchmarkNewTrustKeyStore(b *testing.B) {
	// Setup
	b.Helper()
	keys := map[string]jose.Jwk{
		"issuer": &jose.PublicRsaKey{},
	}
	for _, key := range keys {
		key.SetKid("123456")
	}
	for i := 0; i < b.N; i++ {
		_, _ = NewTrustKeyStore(keys)

	}
}

func TestNewTrustKeyStore(t *testing.T) {
	// Setup
	keys := map[string]jose.Jwk{
		"issuer": &jose.PublicRsaKey{},
	}
	for _, key := range keys {
		key.SetKid("123456")
	}
	// Act
	store, err := NewTrustKeyStore(keys)

	// Assert
	assert.NoError(t, err)
	assert.NotNil(t, store)
}

func TestNewTrustKeyStoreNoKid(t *testing.T) {
	// Setup
	keys := map[string]jose.Jwk{
		"issuer": &jose.PublicRsaKey{},
	}

	// Act
	store, err := NewTrustKeyStore(keys)

	// Assert
	assert.Error(t, err, ErrInvalidKey)
	assert.Nil(t, store)
}

func TestAddExisting(t *testing.T) {
	// Setup
	keys := map[string]jose.Jwk{
		"issuer": &jose.PublicRsaKey{},
	}
	for _, key := range keys {
		key.SetKid("123456")
	}
	// Act
	store, err := NewTrustKeyStore(keys)

	// Assert
	assert.NoError(t, err)
	assert.NotNil(t, store)

	for issuer, jwk := range keys {
		err = store.Add(issuer, jwk)
	}

	// Assert
	assert.NoError(t, err)

}

func TestRemove(t *testing.T) {
	// Setup
	keys := map[string]jose.Jwk{
		"issuer": &jose.PublicRsaKey{},
	}
	for _, key := range keys {
		key.SetKid("123456")
	}
	// Act
	store, err := NewTrustKeyStore(keys)

	// Assert
	assert.NoError(t, err)
	assert.NotNil(t, store)

	for issuer, jwk := range keys {
		result := store.Remove(issuer, jwk.Kid())
		assert.True(t, result)
	}

}

func TestRemoveNoKey(t *testing.T) {
	// Setup
	keys := map[string]jose.Jwk{
		"issuer": &jose.PublicRsaKey{},
	}
	for _, key := range keys {
		key.SetKid("123456")
	}
	// Act
	store, err := NewTrustKeyStore(keys)

	// Assert
	assert.NoError(t, err)
	assert.NotNil(t, store)

	result := store.Remove("invalid", "98765")
	assert.False(t, result)

}

func TestGet(t *testing.T) {
	// Setup
	keys := map[string]jose.Jwk{
		"issuer": &jose.PublicRsaKey{},
	}
	for _, key := range keys {
		key.SetKid("123456")
		key.SetAlg(jose.AlgRS512)
		key.SetOps(validVerificationOps)
	}
	// Act
	store, err := NewTrustKeyStore(keys)

	// Assert
	assert.NoError(t, err)
	assert.NotNil(t, store)

	key, err := store.Get(context.Background(), "issuer", "123456")
	assert.NotNil(t, key)
	assert.Nil(t, err)

}

func TestGetFail(t *testing.T) {
	// Setup
	keys := map[string]jose.Jwk{
		"issuer": &jose.PublicRsaKey{},
	}
	for _, key := range keys {
		key.SetKid("123456")
		key.SetAlg(jose.AlgRS512)
		key.SetOps(validVerificationOps)
	}
	// Act
	store, err := NewTrustKeyStore(keys)

	// Assert
	assert.NoError(t, err)
	assert.NotNil(t, store)

	key, err := store.Get(context.Background(), "unknown", "98765")
	assert.Nil(t, key)
	assert.Equal(t, ErrUnknownKey, err)
}
