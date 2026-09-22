// SPDX-FileCopyrightText: 2026 Thales Group and the gose Contributors
// SPDX-License-Identifier: MIT

package gose

import (
	"crypto/hmac"
	"crypto/sha256"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestHmacShaCryptor(t *testing.T) {
	kid := "hmac-0"
	cryptor := NewHmacShaCryptor(kid, sha256.New())
	t.Run("testHmacKid", func(t *testing.T) {
		testHmacKid(t, cryptor, kid)
	})
	t.Run("testHmacHash", func(t *testing.T) {
		testHmacHash(t, cryptor, []byte("hashme"))
	})
}

func testHmacKid(t *testing.T, cryptor HmacKey, kid string) {
	require.Equal(t, kid, cryptor.Kid())
}

func testHmacHash(t *testing.T, cryptor HmacKey, input []byte) {
	sha := cryptor.Hash(input)
	require.NotEmpty(t, sha)
	require.Equal(t, 32, len(sha))
	require.NotContains(t, string(sha), string(input))
}

// TestHmacShaCryptor_ConcurrentHash pins the fix for concurrent use of one
// HmacShaCryptor. Before the mutex, this test crashed the process with
// "panic: d.nx != 0" from crypto/sha256 (and `go test -race` flagged the
// races on the shared hash.Hash). Every concurrent result must equal the
// sequential one.
func TestHmacShaCryptor_ConcurrentHash(t *testing.T) {
	cryptor := NewHmacShaCryptor("hmac-concurrent", hmac.New(sha256.New, []byte("key")))
	input := []byte("the same message from every goroutine")
	want := cryptor.Hash(input)

	const goroutines, iterations = 32, 200
	var wg sync.WaitGroup
	var mismatches atomic.Int64
	for range goroutines {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range iterations {
				if !hmac.Equal(cryptor.Hash(input), want) {
					mismatches.Add(1)
				}
			}
		}()
	}
	wg.Wait()
	require.Zero(t, mismatches.Load(), "concurrent Hash calls produced wrong MACs")
}
