// SPDX-FileCopyrightText: 2026 Thales Group and the gose Contributors
// SPDX-License-Identifier: MIT

package gose

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"sync"

	"github.com/eclipse-keypont/gose/jose"
)

// TrustKeyStoreImpl implements the Trust Store API
type TrustKeyStoreImpl struct {
	keys map[string]map[string]jose.Jwk
	// revoked records (issuer, kid) pairs that have been removed. A VerificationKey
	// handed out by Get before the removal keeps its own copy of the key material, so
	// deleting the map entry alone does not stop it verifying. Get consults this set so
	// a revoked key stops being trusted even through a previously returned verifier.
	revoked map[string]map[string]struct{}
	mtx     sync.Mutex
}

// Add add an issuer and JWK to the truststore
func (store *TrustKeyStoreImpl) Add(issuer string, jwk jose.Jwk) error {
	if jwk.Kid() == "" {
		// We want a Key ID and we want it now!
		return ErrInvalidKey
	}
	store.mtx.Lock()
	defer store.mtx.Unlock()
	if _, exists := store.keys[issuer]; !exists {
		store.keys[issuer] = make(map[string]jose.Jwk)
	}
	if _, exists := store.keys[issuer][jwk.Kid()]; exists {
		return nil
	}
	store.keys[issuer][jwk.Kid()] = jwk
	return nil
}

// Remove remove JWK for issuer and jwk id
func (store *TrustKeyStoreImpl) Remove(issuer, kid string) bool {
	store.mtx.Lock()
	defer store.mtx.Unlock()
	if _, exists := store.keys[issuer]; !exists {
		return false
	}
	delete(store.keys[issuer], kid)
	// Record the revocation so a verifier obtained before this call stops being trusted.
	if store.revoked == nil {
		store.revoked = make(map[string]map[string]struct{})
	}
	if _, exists := store.revoked[issuer]; !exists {
		store.revoked[issuer] = make(map[string]struct{})
	}
	store.revoked[issuer][kid] = struct{}{}
	return true
}

// Get get verification jwk for issuer and jwk id
func (store *TrustKeyStoreImpl) Get(_ context.Context, issuer, kid string) (vk VerificationKey, err error) {
	store.mtx.Lock()
	defer store.mtx.Unlock()
	// A revoked key is unknown even if it is still present in the map (e.g. re-added
	// after removal): the revocation is sticky until the key is explicitly re-added.
	if revoked, ok := store.revoked[issuer]; ok {
		if _, ok := revoked[kid]; ok {
			return nil, ErrUnknownKey
		}
	}
	if keySet, ok := store.keys[issuer]; ok {
		if jwk, ok := keySet[kid]; ok {
			if key, err := NewVerificationKey(jwk); err == nil {
				return key, nil
			}
			return nil, err
		}
	}
	return nil, ErrUnknownKey
}

// NewTrustKeyStore loads truststore for map of jose.JWK
func NewTrustKeyStore(rootData map[string]jose.Jwk) (store *TrustKeyStoreImpl, err error) {
	tmp := TrustKeyStoreImpl{}
	tmp.keys = make(map[string]map[string]jose.Jwk)
	tmp.revoked = make(map[string]map[string]struct{})
	for issuer, jwk := range rootData {
		if err = tmp.Add(issuer, jwk); err != nil {
			return
		}
	}
	store = &tmp
	return
}

// NewTrustKeyStoreFromFile loads truststore for a
func NewTrustKeyStoreFromFile(root string) (store *TrustKeyStoreImpl, err error) {
	tmp := TrustKeyStoreImpl{}
	tmp.keys = make(map[string]map[string]jose.Jwk)
	tmp.revoked = make(map[string]map[string]struct{})
	var entries map[string]json.RawMessage
	// Bound the read: the file is caller-supplied and os.ReadFile would otherwise
	// allocate whatever size the file reports. Stat first so a huge or special file is
	// rejected before it is read.
	info, err := os.Stat(root)
	if err != nil {
		return nil, err
	}
	if info.Size() > MaxKeyFileSize {
		return nil, ErrInputTooLarge
	}
	rootData, err := os.ReadFile(root) // #nosec G304 -- file path is a caller-supplied argument to this public API
	if err != nil {
		return nil, err
	}
	if err = json.Unmarshal(rootData, &entries); err != nil {
		return
	}
	for issuer, entry := range entries {
		var jwk jose.Jwk
		if jwk, err = jose.UnmarshalJwk(bytes.NewReader([]byte(entry))); err != nil {
			return
		}
		if err = tmp.Add(issuer, jwk); err != nil {
			return
		}
	}
	store = &tmp
	return
}
