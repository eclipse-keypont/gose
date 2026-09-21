// SPDX-FileCopyrightText: 2026 Thales Group and the gose Contributors
// SPDX-License-Identifier: MIT

package gose

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/eclipse-keypont/gose/jose"
)

// maxJwksBytes bounds how much of a JWKS response is read. Real key sets are a few
// kilobytes; the cap keeps a hostile or misconfigured endpoint from handing us an
// unbounded body to parse.
const maxJwksBytes = 1 << 20 // 1 MiB

// Interface wrapper to allow mocking of http client.
type httpClient interface {
	Do(req *http.Request) (resp *http.Response, err error)
}

// JwksTrustStore is an implementation of the TrustStore interface and can be used for accessing VerificationKeys.
type JwksTrustStore struct {
	lock         sync.Mutex
	url          string
	inputIssuers string //csv of issuers
	issuers      []string
	keys         []VerificationKey
	client       httpClient
}

// Add this method is not supported on a JwksTrustStore instance and will always return an error.
func (store *JwksTrustStore) Add(_ string, _ jose.Jwk) error {
	return errors.New("read-only trust store")
}

// Remove this method is not supported on a JwksTrustStore instance and will always return false.
func (store *JwksTrustStore) Remove(_, _ string) bool {
	return false
}

// Get returns a verification key for the given issuer and key id. If no key is found nil is returned.
func (store *JwksTrustStore) Get(ctx context.Context, issuer, kid string) (vk VerificationKey, err error) {
	store.lock.Lock()
	defer store.lock.Unlock()

	foundIssuer := false

	//lazy instantiation of the issuer list
	if len(store.issuers) == 0 {
		store.issuers = strings.Split(store.inputIssuers, ",")
	}

	//search our list for the provided issuer
	for _, issuerInStore := range store.issuers {
		if issuerInStore == issuer {
			foundIssuer = true
			break
		}
	}

	//is the provided issuer in our list?
	if foundIssuer {

		for _, key := range store.keys {
			if key.Kid() == kid {
				vk = key
				return
			}
		}
		// Not found. Refresh the keys
		var response *http.Response
		var req *http.Request
		if req, err = http.NewRequestWithContext(ctx, http.MethodGet, store.url, nil); err != nil {
			err = fmt.Errorf("error creating request for JWKS from %s: %w", store.url, err)
			return
		}
		response, err = store.client.Do(req)
		if err != nil {
			err = fmt.Errorf("error encountered retrieving JWKS from %s: %w", store.url, err)
			return
		}
		defer func() { _ = response.Body.Close() }()
		if response.StatusCode != http.StatusOK {
			err = fmt.Errorf("error encountered retrieving JWKS from %s: %d %s", store.url, response.StatusCode, response.Status)
			return
		}
		// Bound the response: the body is remote input and parsing it is not free.
		decoder := json.NewDecoder(io.LimitReader(response.Body, maxJwksBytes))
		var jwks jose.Jwks
		if err = decoder.Decode(&jwks); err != nil {
			err = fmt.Errorf("error encountered retrieving JWKS from %s: invalid encoding", store.url)
			return
		}
		keys := make([]VerificationKey, 0, len(jwks.Keys))
		for _, jwk := range jwks.Keys {
			// Deliberately a local, not the named return: assigning to vk here left the
			// last-parsed key in the named return, so the "not found" fall-through below
			// handed the caller that key with a nil error instead of nothing.
			key, keyErr := NewVerificationKey(jwk)
			if keyErr != nil {
				return nil, fmt.Errorf("failed to load verification key from JWK: %w", keyErr)
			}
			keys = append(keys, key)
		}
		// Replace the keys for our store.
		store.keys = keys

		// Try and find key in newly cached keys
		for _, key := range store.keys {
			if key.Kid() == kid {
				return key, nil
			}
		}
	}
	// No such currently valid key or issuer. Explicit, so that neither a stale vk nor a
	// stale err can leak out through a naked return.
	return nil, nil
}

// NewJwksKeyStore creates a new instance of a TrustStore and can be used to load verification keys.
func NewJwksKeyStore(issuerList, url string) *JwksTrustStore {
	return &JwksTrustStore{
		url:          url,
		inputIssuers: issuerList,
		client: &http.Client{
			Timeout: time.Second * 30,
		},
	}
}
