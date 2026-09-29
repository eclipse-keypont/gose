// SPDX-FileCopyrightText: 2026 Thales Group and the gose Contributors
// SPDX-License-Identifier: MIT

package gose

import (
	"fmt"
	"hash"
	"reflect"
	"strings"
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

// isHmac reports whether h is a keyed MAC from crypto/hmac rather than a bare digest.
// crypto/hmac's concrete type is unexported, so its name and package are the only way to
// tell the two apart without changing the constructor's signature. Since Go 1.24
// crypto/hmac is a thin wrapper over crypto/internal/fips140/hmac, so the package path is
// matched loosely rather than against "crypto/hmac" exactly.
func isHmac(h hash.Hash) bool {
	t := reflect.TypeOf(h)
	if t == nil {
		return false
	}
	if t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	return t.Name() == "HMAC" && strings.Contains(t.PkgPath(), "hmac")
}

// NewHmacShaCryptor create a new instance of an HmacShaCryptor from the supplied parameters.
// It implements HmacKey.
//
// hash must be a keyed MAC (crypto/hmac), not a bare digest. HmacShaCryptor.Hash is used
// as the JWE authentication tag, and a bare digest is unkeyed — anyone can recompute it,
// so it authenticates nothing. A non-HMAC hash.Hash is rejected rather than silently used
// as an authentication tag.
func NewHmacShaCryptor(kid string, hash hash.Hash) HmacKey {
	if !isHmac(hash) {
		panic(fmt.Sprintf("gose: NewHmacShaCryptor requires a crypto/hmac MAC, got %T", hash))
	}
	return &HmacShaCryptor{
		kid:  kid,
		hash: hash,
	}
}
