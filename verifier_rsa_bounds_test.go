// SPDX-FileCopyrightText: 2026 Thales Group and the gose Contributors
// SPDX-License-Identifier: MIT

package gose

import (
	"crypto/rand"
	"crypto/rsa"
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/eclipse-keypont/gose/jose"
)

// NewVerificationKey must apply the same RSA modulus and exponent bounds as LoadPublicKey,
// so a key that import would reject cannot slip in through the verification path.

func TestNewVerificationKey_RejectsUndersizedRsaModulus(t *testing.T) {
	small, err := rsa.GenerateKey(rand.Reader, 1024)
	require.NoError(t, err)

	var k jose.PublicRsaKey
	k.N.SetBytes(small.N.Bytes())
	k.E.SetBytes(big.NewInt(int64(small.E)).Bytes())
	k.SetKid("small")
	k.SetAlg(jose.AlgRS256)

	// LoadPublicKey already rejects it; NewVerificationKey must agree.
	_, err = LoadPublicKey(&k, nil)
	require.ErrorIs(t, err, ErrInvalidKeySize)
	_, err = NewVerificationKey(&k)
	require.ErrorIs(t, err, ErrInvalidKeySize)
}

func TestNewVerificationKey_RejectsOversizedRsaExponent(t *testing.T) {
	good, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	var k jose.PublicRsaKey
	k.N.SetBytes(good.N.Bytes())
	// e = 2^64 + 65537: more than 32 bits, and above what big.Int.Int64 represents, so the
	// old MaxInt32 test silently truncated it to 65537 and verified with the wrong key.
	hugeE := new(big.Int).Add(new(big.Int).Lsh(big.NewInt(1), 64), big.NewInt(65537))
	k.E.SetBytes(hugeE.Bytes())
	k.SetKid("huge-e")
	k.SetAlg(jose.AlgRS256)

	_, err = LoadPublicKey(&k, nil)
	require.ErrorIs(t, err, ErrInvalidExponent)
	_, err = NewVerificationKey(&k)
	require.ErrorIs(t, err, ErrInvalidExponent)
}

func TestNewVerificationKey_AcceptsConformingRsaKey(t *testing.T) {
	good, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	jwk, err := JwkFromPublicKey(good.Public(), []jose.KeyOps{jose.KeyOpsVerify}, nil)
	require.NoError(t, err)
	jwk.SetAlg(jose.AlgRS256)

	vk, err := NewVerificationKey(jwk)
	require.NoError(t, err)
	require.NotNil(t, vk)
}
