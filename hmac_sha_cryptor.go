// SPDX-FileCopyrightText: 2026 Thales Group and the gose Contributors
// SPDX-License-Identifier: MIT

package gose

import (
	"hash"
	"sync"
)

// HmacShaCryptor provides HMAC SHA functions.
// It implements the HmacKey interface.
// The hash SHA mechanism is held directly by the key corresponding to the key id (kid).
// It means that if the key provides SHA-256 mechanism, then the Hash is SHA-256
//
// A single instance is safe for concurrent use: the underlying hash.Hash is
// stateful (Reset/Write/Sum), and the same instance is routinely shared between
// an encryptor and a decryptor, or across the goroutines of a server.
type HmacShaCryptor struct {
	kid string
	// mu serialises access to hash. Interleaving Reset/Write/Sum from two
	// goroutines does not merely produce a wrong MAC: crypto/sha256 panics
	// ("d.nx != 0") when Sum sees a block buffer another writer left half-full,
	// taking the process down.
	mu   sync.Mutex
	hash hash.Hash
}

// Kid returns the identity of the key.
func (h *HmacShaCryptor) Kid() string {
	return h.kid
}

// Hash returns the HMAC of input using the underlying hash key.
// Reset is called before each use so that the same instance can be safely
// called multiple times (e.g. shared between encryptor and verifier).
func (h *HmacShaCryptor) Hash(input []byte) []byte {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.hash.Reset()
	if _, err := h.hash.Write(input); err != nil {
		panic(err)
	}
	return h.hash.Sum(nil)
}

// NewHmacShaCryptor create a new instance of an HmacShaCryptor from the supplied parameters.
// It implements HmacKey
func NewHmacShaCryptor(kid string, hash hash.Hash) HmacKey {
	return &HmacShaCryptor{
		kid:  kid,
		hash: hash,
	}
}
