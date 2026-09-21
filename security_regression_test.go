// SPDX-FileCopyrightText: 2026 Thales Group and the gose Contributors
// SPDX-License-Identifier: MIT

package gose

import (
	"context"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/eclipse-keypont/gose/jose"
)

// newTestGcmCryptor builds an AES-256-GCM cryptor over a fixed key.
func newTestGcmCryptor(t *testing.T, ops ...jose.KeyOps) AeadEncryptionKey {
	t.Helper()
	block, err := aes.NewCipher(make([]byte, 32))
	require.NoError(t, err)
	aead, err := cipher.NewGCM(block)
	require.NoError(t, err)
	cryptor, err := NewAesGcmCryptor(aead, rand.Reader, "kid", jose.AlgA256GCM, ops)
	require.NoError(t, err)
	return cryptor
}

// AesGcmCryptor.Open used to hand an unchecked nonce to cipher.AEAD.Open, which panics
// rather than erroring when the nonce is not exactly NonceSize bytes. The nonce is
// attacker-controlled on the decryption path.
func TestAesGcmCryptorOpenRejectsWrongSizedNonce(t *testing.T) {
	cryptor := newTestGcmCryptor(t, jose.KeyOpsDecrypt)
	validTag := make([]byte, 16)

	for _, nonceLen := range []int{0, 1, 7, 11, 13, 32} {
		t.Run(fmt.Sprintf("nonce_len_%d", nonceLen), func(t *testing.T) {
			_, err := cryptor.Open(jose.KeyOpsDecrypt, make([]byte, nonceLen),
				[]byte("ciphertext"), nil, validTag)
			assert.ErrorIs(t, err, ErrInvalidNonce)
		})
	}
}

// A wrong-sized tag cannot authenticate; it should be reported precisely rather than as
// an opaque authentication failure.
func TestAesGcmCryptorOpenRejectsWrongSizedTag(t *testing.T) {
	cryptor := newTestGcmCryptor(t, jose.KeyOpsDecrypt)
	validNonce := make([]byte, 12)

	for _, tagLen := range []int{0, 1, 15, 17, 32} {
		t.Run(fmt.Sprintf("tag_len_%d", tagLen), func(t *testing.T) {
			_, err := cryptor.Open(jose.KeyOpsDecrypt, validNonce,
				[]byte("ciphertext"), nil, make([]byte, tagLen))
			assert.ErrorIs(t, err, ErrInvalidAuthenticationTag)
		})
	}
}

// A correctly sized nonce and tag must still reach the AEAD and fail authentication,
// proving the guards above reject on length alone and do not short-circuit valid input.
func TestAesGcmCryptorOpenCorrectSizesReachAead(t *testing.T) {
	cryptor := newTestGcmCryptor(t, jose.KeyOpsDecrypt)
	_, err := cryptor.Open(jose.KeyOpsDecrypt, make([]byte, 12),
		[]byte("ciphertext"), nil, make([]byte, 16))
	require.Error(t, err)
	assert.NotErrorIs(t, err, ErrInvalidNonce)
	assert.NotErrorIs(t, err, ErrInvalidAuthenticationTag)
}

// stubRsaDecryptionKey is the minimum AsymmetricDecryptionKey needed to drive
// JweRsaKeyEncryptionDecryptorImpl without an HSM.
type stubRsaDecryptionKey struct {
	kid  string
	priv *rsa.PrivateKey
}

func (k *stubRsaDecryptionKey) Kid() string              { return k.kid }
func (k *stubRsaDecryptionKey) Jwk() (jose.Jwk, error)   { return nil, nil }
func (k *stubRsaDecryptionKey) Marshal() (string, error) { return "", nil }
func (k *stubRsaDecryptionKey) MarshalPem() (string, error) {
	return "", nil
}
func (k *stubRsaDecryptionKey) Algorithm() jose.Alg { return jose.AlgRSAOAEP }
func (k *stubRsaDecryptionKey) Encryptor() (AsymmetricEncryptionKey, error) {
	return nil, fmt.Errorf("not implemented")
}
func (k *stubRsaDecryptionKey) Decrypt(_ jose.KeyOps, hash crypto.Hash, ct []byte) ([]byte, error) {
	return rsa.DecryptOAEP(hash.New(), rand.Reader, k.priv, ct, nil)
}

type stubDecryptionKeystore struct{ key AsymmetricDecryptionKey }

func (s *stubDecryptionKeystore) Get(kid string) (AsymmetricDecryptionKey, error) {
	if kid != s.key.Kid() {
		return nil, fmt.Errorf("no such key %q", kid)
	}
	return s.key, nil
}

// buildRsaOaepJwe assembles a compact JWE whose IV and tag lengths are caller-chosen.
// The CEK is genuinely wrapped under the recipient's public key, which is all an
// attacker needs to reach the decryptor's AEAD.
func buildRsaOaepJwe(t *testing.T, pub *rsa.PublicKey, ivLen, tagLen int) string {
	t.Helper()
	cek := make([]byte, 32)
	_, err := rand.Read(cek)
	require.NoError(t, err)
	// RFC 7518 §4.3: "RSA-OAEP" means SHA-1.
	wrapped, err := rsa.EncryptOAEP(crypto.SHA1.New(), rand.Reader, pub, cek, nil)
	require.NoError(t, err)

	b64 := base64.RawURLEncoding.EncodeToString
	header, err := json.Marshal(map[string]any{
		"alg": "RSA-OAEP", "enc": "A256GCM", "kid": "k1",
	})
	require.NoError(t, err)
	return strings.Join([]string{
		b64(header), b64(wrapped), b64(make([]byte, ivLen)),
		b64([]byte("ciphertext")), b64(make([]byte, tagLen)),
	}, ".")
}

// JweRsaKeyEncryptionDecryptorImpl.Decrypt reached cipher.AEAD.Open with an unchecked
// IV. Reaching it needs only the recipient's public key, so this was triggerable by any
// party able to fetch that key.
func TestJweRsaKeyEncryptionDecryptorRejectsWrongSizedIV(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	decryptor := NewJweRsaKeyEncryptionDecryptorImpl(&stubDecryptionKeystore{
		key: &stubRsaDecryptionKey{kid: "k1", priv: priv},
	})

	for _, ivLen := range []int{0, 7, 11, 13, 32} {
		t.Run(fmt.Sprintf("iv_len_%d", ivLen), func(t *testing.T) {
			jwe := buildRsaOaepJwe(t, &priv.PublicKey, ivLen, 16)
			_, _, err := decryptor.Decrypt(jwe, crypto.Hash(0))
			assert.ErrorIs(t, err, ErrInvalidNonce)
		})
	}
}

func TestJweRsaKeyEncryptionDecryptorRejectsWrongSizedTag(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	decryptor := NewJweRsaKeyEncryptionDecryptorImpl(&stubDecryptionKeystore{
		key: &stubRsaDecryptionKey{kid: "k1", priv: priv},
	})

	for _, tagLen := range []int{0, 15, 17} {
		t.Run(fmt.Sprintf("tag_len_%d", tagLen), func(t *testing.T) {
			jwe := buildRsaOaepJwe(t, &priv.PublicKey, 12, tagLen)
			_, _, err := decryptor.Decrypt(jwe, crypto.Hash(0))
			assert.ErrorIs(t, err, ErrInvalidAuthenticationTag)
		})
	}
}

// LoadPublicKey and LoadPrivateKey asserted algToOptsMap[alg] to *ECDSAOptions without
// the comma-ok form. RFC 7517 §4.4 allows an EC key to carry any "alg", and
// jose.UnmarshalJwk picks the Go type from "kty" alone, so the mismatch is reachable
// from any externally supplied JWK document.
func TestLoadPublicKeyRejectsKtyAlgMismatch(t *testing.T) {
	for _, alg := range []string{"RS256", "RS384", "PS256", "RSA-OAEP", "RSA-OAEP-256"} {
		t.Run(alg, func(t *testing.T) {
			doc := fmt.Sprintf(
				`{"kty":"EC","alg":"%s","crv":"P-256","x":"AQ","y":"AQ","key_ops":["verify"]}`, alg)
			jwk, err := jose.UnmarshalJwk(strings.NewReader(doc))
			require.NoError(t, err)
			require.IsType(t, &jose.PublicEcKey{}, jwk)

			key, err := LoadPublicKey(jwk, nil)
			assert.Nil(t, key)
			assert.ErrorIs(t, err, ErrInvalidKeyType)
		})
	}
}

// A matching kty/alg pair must still load, so the guard above is not over-broad.
func TestLoadPublicKeyAcceptsMatchingEcAlg(t *testing.T) {
	doc := `{"kty":"EC","alg":"ES256","crv":"P-256",` +
		`"x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",` +
		`"y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0","key_ops":["verify"]}`
	jwk, err := jose.UnmarshalJwk(strings.NewReader(doc))
	require.NoError(t, err)

	key, err := LoadPublicKey(jwk, nil)
	require.NoError(t, err)
	assert.NotNil(t, key)
}

// jwksHandler serves a static JWKS containing the given kids.
func jwksHandler(t *testing.T, kids ...string) *httptest.Server {
	t.Helper()
	entries := make([]string, 0, len(kids))
	for _, kid := range kids {
		entries = append(entries, fmt.Sprintf(
			`{"kty":"EC","kid":"%s","alg":"ES256","crv":"P-256",`+
				`"x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",`+
				`"y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",`+
				`"key_ops":["verify"]}`, kid))
	}
	body := fmt.Sprintf(`{"keys":[%s]}`, strings.Join(entries, ","))
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
}

// JwksTrustStore.Get assigned each parsed key to its *named return*, so when the
// requested kid was absent the trailing naked return handed back the last key in the
// JWKS with a nil error. That silently breaks the kid-to-key binding: a token naming
// one kid would be verified against a different key.
func TestJwksTrustStoreGetReturnsNilForAbsentKid(t *testing.T) {
	srv := jwksHandler(t, "first", "last")
	defer srv.Close()

	store := NewJwksKeyStore("issuer1", srv.URL)
	key, err := store.Get(context.Background(), "issuer1", "does-not-exist")
	require.NoError(t, err)
	assert.Nil(t, key, "absent kid must not resolve to another key in the JWKS")
}

func TestJwksTrustStoreGetReturnsNilForAbsentIssuer(t *testing.T) {
	srv := jwksHandler(t, "first", "last")
	defer srv.Close()

	store := NewJwksKeyStore("issuer1", srv.URL)
	key, err := store.Get(context.Background(), "other-issuer", "first")
	require.NoError(t, err)
	assert.Nil(t, key)
}

// The present kid must still resolve, so the fix does not simply break lookup.
func TestJwksTrustStoreGetFindsPresentKid(t *testing.T) {
	srv := jwksHandler(t, "first", "last")
	defer srv.Close()

	store := NewJwksKeyStore("issuer1", srv.URL)
	for _, kid := range []string{"first", "last"} {
		key, err := store.Get(context.Background(), "issuer1", kid)
		require.NoError(t, err)
		require.NotNil(t, key)
		assert.Equal(t, kid, key.Kid())
	}
}
