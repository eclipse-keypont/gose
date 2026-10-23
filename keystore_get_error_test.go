// SPDX-FileCopyrightText: 2026 Thales Group and the gose Contributors
// SPDX-License-Identifier: MIT

package gose

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/eclipse-keypont/gose/jose"
)

// Get must surface the error from NewVerificationKey rather than returning (nil, nil)
// for a stored key it cannot turn into a verifier. A caller that checks err before using
// the key would otherwise dereference a nil VerificationKey.
func TestGet_UnusableKeyReturnsError(t *testing.T) {
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	jwk, err := JwkFromPublicKey(&ecKey.PublicKey, []jose.KeyOps{jose.KeyOpsVerify}, nil)
	require.NoError(t, err)
	jwk.SetKid("123456")
	jwk.SetAlg("") // without an alg, NewVerificationKey cannot build an EC verifier

	store, err := NewTrustKeyStore(map[string]jose.Jwk{"issuer": jwk})
	require.NoError(t, err)

	key, err := store.Get(context.Background(), "issuer", "123456")
	require.Error(t, err, "Get must not hide NewVerificationKey's failure")
	require.Nil(t, key)
}
