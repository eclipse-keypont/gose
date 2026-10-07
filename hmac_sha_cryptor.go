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
	// destroyed records that Destroy has been called. crypto/hmac keeps the key
	// in an internal, unexported state that cannot be zeroized in place, so
	// Destroy drops the reference and refuses further use instead.
	destroyed bool
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
	if h.destroyed {
		panic("gose: Hash called on a destroyed HmacShaCryptor")
	}
	h.hash.Reset()
	if _, err := h.hash.Write(input); err != nil {
		panic(err)
	}
	return h.hash.Sum(nil)
}

// Destroy releases the keyed MAC held by the cryptor. crypto/hmac keeps the key
// in an internal, unexported state that cannot be zeroized in place, so Destroy
// drops the reference — making the key material unreachable and eligible for
// collection — and marks the cryptor unusable; a later Hash panics. It is
// idempotent and safe to call concurrently with Hash, but must not be called
// while an operation is in flight.
func (h *HmacShaCryptor) Destroy() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.destroyed = true
	h.hash = nil
}

// KeyedHash is a hash.Hash that is a keyed MAC (HMAC) rather than a bare digest.
//
// crypto/hmac's concrete type is unexported, so a keyed MAC cannot be recognised
// by type assertion alone. A keyed MAC implemented outside crypto/hmac — for
// example an HSM-backed HMAC — opts in by implementing this interface, which lets
// NewHmacShaCryptor accept it while still rejecting an unkeyed digest such as
// sha256.New(). The interface is structural: an implementation satisfies it
// without importing gose.
type KeyedHash interface {
	hash.Hash
	// IsKeyedHash marks the implementation as a keyed MAC. It carries no
	// behaviour; it exists only to make keyed-ness explicit and checkable.
	IsKeyedHash()
}

// isHmac reports whether h is a keyed MAC rather than a bare digest.
//
// A keyed MAC is recognised either by the explicit KeyedHash opt-in, or — for
// crypto/hmac, whose concrete type is unexported — by its name and package. Since
// Go 1.24 crypto/hmac is a thin wrapper over crypto/internal/fips140/hmac, so the
// package path is matched loosely rather than against "crypto/hmac" exactly.
func isHmac(h hash.Hash) bool {
	if _, ok := h.(KeyedHash); ok {
		return true
	}
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
// hash must be a keyed MAC, not a bare digest: either a crypto/hmac MAC or a type
// implementing KeyedHash (for example an HSM-backed HMAC). HmacShaCryptor.Hash is
// used as the JWE authentication tag, and a bare digest is unkeyed — anyone can
// recompute it, so it authenticates nothing. A non-HMAC hash.Hash is rejected
// rather than silently used as an authentication tag.
func NewHmacShaCryptor(kid string, hash hash.Hash) HmacKey {
	if !isHmac(hash) {
		panic(fmt.Sprintf("gose: NewHmacShaCryptor requires a keyed MAC (crypto/hmac or gose.KeyedHash), got %T", hash))
	}
	return &HmacShaCryptor{
		kid:  kid,
		hash: hash,
	}
}
