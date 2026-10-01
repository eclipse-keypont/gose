// SPDX-FileCopyrightText: 2026 Thales Group and the gose Contributors
// SPDX-License-Identifier: MIT

package gose

import (
	"context"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
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

// NewHmacShaCryptor accepted any hash.Hash, so a bare digest (sha256.New) could be
// installed as the JWE authentication tag. A bare digest is unkeyed — anyone can
// recompute it — so it authenticates nothing. Only a crypto/hmac MAC is accepted.
func TestNewHmacShaCryptorRejectsBareDigest(t *testing.T) {
	assert.Panics(t, func() { NewHmacShaCryptor("k", sha256.New()) },
		"a bare digest must not be accepted as an authentication tag")
	require.NotPanics(t, func() { NewHmacShaCryptor("k", hmac.New(sha256.New, []byte("key"))) })
}

// RsaPublicKeyImpl.Verify fell through to VerifyPKCS1v15 for any non-PSS alg, so a key
// labelled RSA-OAEP — which NewRsaPublicKeyImpl admits — verified PKCS#1 v1.5 signatures
// under an algorithm it does not name.
func TestRsaPublicKeyVerifyRejectsNonSignatureAlg(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	digest := sha256.Sum256([]byte("message"))
	sig, err := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, digest[:])
	require.NoError(t, err)

	jwk, err := JwkFromPublicKey(priv.Public(), []jose.KeyOps{jose.KeyOpsVerify}, nil)
	require.NoError(t, err)
	jwk.SetAlg(jose.AlgRS256)
	key, err := NewRsaPublicKeyImpl(jwk)
	require.NoError(t, err)
	require.True(t, key.Verify(jose.KeyOpsVerify, []byte("message"), sig))

	// Relabel as RSA-OAEP: the same signature must no longer verify.
	jwk.SetAlg(jose.AlgRSAOAEP)
	key, err = NewRsaPublicKeyImpl(jwk)
	require.NoError(t, err)
	assert.False(t, key.Verify(jose.KeyOpsVerify, []byte("message"), sig),
		"a key labelled RSA-OAEP must not verify a PKCS#1 v1.5 signature")
}

// Remove deleted the map entry but a VerificationKey handed out earlier kept its own copy
// of the key material, so a revoked key kept verifying. Get must treat a removed key as
// unknown even through a previously returned verifier.
func TestTrustKeyStoreRemoveInvalidatesVerifier(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	jwk, err := JwkFromPublicKey(priv.Public(), []jose.KeyOps{jose.KeyOpsVerify}, nil)
	require.NoError(t, err)
	store, err := NewTrustKeyStore(map[string]jose.Jwk{"issuer": jwk})
	require.NoError(t, err)

	key, err := store.Get(context.Background(), "issuer", jwk.Kid())
	require.NoError(t, err)
	require.NotNil(t, key)

	require.True(t, store.Remove("issuer", jwk.Kid()))
	_, err = store.Get(context.Background(), "issuer", jwk.Kid())
	assert.ErrorIs(t, err, ErrUnknownKey, "a removed key must not be returned")
}

// RFC 7518 §3.5 requires an RSA modulus of at least 2048 bits. LoadPublicKey accepted
// any modulus, so an undersized key imported from a JWK was used for verification.
func TestLoadPublicKeyRejectsUndersizedRsaModulus(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	require.NoError(t, err)
	jwk, err := JwkFromPublicKey(&key.PublicKey, []jose.KeyOps{jose.KeyOpsVerify}, nil)
	require.NoError(t, err)

	_, err = LoadPublicKey(jwk, nil)
	assert.ErrorIs(t, err, ErrInvalidKeySize)
}

// LoadPrivateKey had the same gap on the signing/decryption path.
func TestLoadPrivateKeyRejectsUndersizedRsaModulus(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	require.NoError(t, err)
	jwk, err := JwkFromPrivateKey(key, []jose.KeyOps{jose.KeyOpsSign}, nil)
	require.NoError(t, err)

	_, err = LoadPrivateKey(jwk, nil)
	assert.ErrorIs(t, err, ErrInvalidKeySize)
}

// A key at the minimum must still load, so the guard is not over-broad.
func TestLoadPublicKeyAcceptsMinimumRsaModulus(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	jwk, err := JwkFromPublicKey(&key.PublicKey, []jose.KeyOps{jose.KeyOpsVerify}, nil)
	require.NoError(t, err)

	_, err = LoadPublicKey(jwk, nil)
	require.NoError(t, err)
}

// NewTrustKeyStoreFromFile read the whole file with os.ReadFile, so a huge or special
// file was materialised in full. The read is now bounded by MaxKeyFileSize.
func TestNewTrustKeyStoreFromFileRejectsOversizedFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "trust.json")
	require.NoError(t, os.WriteFile(path, make([]byte, MaxKeyFileSize+1), 0o600))

	_, err := NewTrustKeyStoreFromFile(path)
	assert.ErrorIs(t, err, ErrInputTooLarge)
}

// AesCbcCryptor.trimSize padded the input into a buffer larger than the input itself,
// with no bound on the input length.
func TestAesCbcCryptorRejectsOversizedPlaintext(t *testing.T) {
	block, err := aes.NewCipher(make([]byte, 32))
	require.NoError(t, err)
	cryptor := NewAesCbcCryptor(cipher.NewCBCEncrypter(block, make([]byte, aes.BlockSize)),
		"kid", jose.AlgA256CBC)

	assert.Nil(t, cryptor.Seal(make([]byte, MaxPlaintextSize+1)))
	assert.Nil(t, cryptor.Open(make([]byte, MaxPlaintextSize+1)))
}

// AesGcmCryptor.Open copied the attacker-supplied ciphertext into a fresh buffer before
// authenticating it.
func TestAesGcmCryptorOpenRejectsOversizedCiphertext(t *testing.T) {
	cryptor := newTestGcmCryptor(t, jose.KeyOpsDecrypt)
	_, err := cryptor.Open(jose.KeyOpsDecrypt, make([]byte, 12),
		make([]byte, MaxPlaintextSize+1), nil, make([]byte, 16))
	assert.ErrorIs(t, err, ErrInputTooLarge)
}

// JwtVerifierImpl.Verify parsed the token before any size check.
func TestJwtVerifierRejectsOversizedToken(t *testing.T) {
	store, err := NewTrustKeyStore(map[string]jose.Jwk{})
	require.NoError(t, err)
	verifier := NewJwtVerifier(store)

	_, _, err = verifier.Verify(strings.Repeat("a", jose.MaxCompactSize+1), []string{"aud"})
	assert.ErrorIs(t, err, ErrInputTooLarge)
}

// Every JWE decryptor parsed the compact string before any size check.
func TestJweDecryptorsRejectOversizedInput(t *testing.T) {
	oversized := strings.Repeat("a", jose.MaxCompactSize+1)

	aead := NewJweDirectDecryptorAeadImpl(nil)
	_, _, err := aead.Decrypt(oversized)
	assert.ErrorIs(t, err, ErrInputTooLarge)

	block := NewJweDirectDecryptorBlock(nil, nil)
	_, _, err = block.Decrypt(oversized)
	assert.ErrorIs(t, err, ErrInputTooLarge)

	rsaDec := NewJweRsaKeyEncryptionDecryptorImpl(nil)
	_, _, err = rsaDec.Decrypt(oversized, crypto.Hash(0))
	assert.ErrorIs(t, err, ErrInputTooLarge)
}

// SigningKeyImpl read jwk.Ops() on every Sign, so a caller holding the JWK could widen
// its key_ops after construction and turn a sign-only key into a signing oracle for
// operations it was never granted (CWE-471, mutable JWK metadata).
func TestSigningKeyCapturesOpsAtConstruction(t *testing.T) {
	gen := &RsaSigningKeyGenerator{}
	key, err := gen.Generate(jose.AlgRS256, 2048, []jose.KeyOps{jose.KeyOpsSign})
	require.NoError(t, err)

	jwk, err := key.Jwk()
	require.NoError(t, err)
	// Widen the JWK's key_ops after the key was built.
	jwk.SetOps([]jose.KeyOps{jose.KeyOpsSign, jose.KeyOpsVerify})

	// The captured policy must still refuse an operation that was never granted.
	_, err = key.Sign(jose.KeyOpsVerify, []byte("data"))
	assert.ErrorIs(t, err, ErrInvalidOperations)

	// And the granted operation must still work.
	_, err = key.Sign(jose.KeyOpsSign, []byte("data"))
	require.NoError(t, err)
}

// SigningKeyImpl read jwk.Alg() on every Sign, so relabelling the JWK after construction
// changed the digest and signature scheme the key used (CWE-471).
func TestSigningKeyCapturesAlgAtConstruction(t *testing.T) {
	gen := &RsaSigningKeyGenerator{}
	key, err := gen.Generate(jose.AlgRS256, 2048, []jose.KeyOps{jose.KeyOpsSign})
	require.NoError(t, err)

	jwk, err := key.Jwk()
	require.NoError(t, err)
	jwk.SetAlg(jose.AlgRS512)

	assert.Equal(t, jose.AlgRS256, key.Algorithm(),
		"algorithm must be fixed at construction, not read from the mutable JWK")
}

// AesGcmCryptor aliased the caller's operations slice, so mutating it after construction
// changed the cryptor's authorization policy (CWE-471).
func TestAesGcmCryptorCapturesOpsAtConstruction(t *testing.T) {
	block, err := aes.NewCipher(make([]byte, 32))
	require.NoError(t, err)
	aead, err := cipher.NewGCM(block)
	require.NoError(t, err)

	ops := []jose.KeyOps{jose.KeyOpsEncrypt}
	cryptor, err := NewAesGcmCryptor(aead, rand.Reader, "kid", jose.AlgA256GCM, ops)
	require.NoError(t, err)

	// Mutate the caller-owned slice after construction.
	ops[0] = jose.KeyOpsDecrypt

	nonce := make([]byte, 12)

	// The granted operation must still work.
	_, _, err = cryptor.Seal(jose.KeyOpsEncrypt, nonce, []byte("plaintext"), nil)
	require.NoError(t, err)

	// The operation the caller tried to substitute must be refused.
	_, _, err = cryptor.Seal(jose.KeyOpsDecrypt, nonce, []byte("plaintext"), nil)
	assert.ErrorIs(t, err, ErrInvalidOperations)
}

// Key generators stored the caller's operations slice by reference, so a caller that
// reused or mutated the slice changed the generated key's policy (CWE-471).
func TestKeyGeneratorClonesOperations(t *testing.T) {
	ops := []jose.KeyOps{jose.KeyOpsSign}
	gen := &RsaSigningKeyGenerator{}
	key, err := gen.Generate(jose.AlgRS256, 2048, ops)
	require.NoError(t, err)

	// Mutate the caller-owned slice after generation.
	ops[0] = jose.KeyOpsVerify

	// The key must still be scoped to sign.
	_, err = key.Sign(jose.KeyOpsSign, []byte("data"))
	require.NoError(t, err)
	_, err = key.Sign(jose.KeyOpsVerify, []byte("data"))
	assert.ErrorIs(t, err, ErrInvalidOperations)
}

// M-G5: the JWT parser used to default a missing "exp" to math.MaxInt64, so a token
// without an expiry never failed the verifier's Expiration <= now check and lived
// forever. A zero Expiration is in the past, so the verifier now rejects it.
func TestJwtVerifyRejectsTokenWithoutExpiration(t *testing.T) {
	generator := &RsaSigningKeyGenerator{}
	signingKey, err := generator.Generate(jose.AlgRS256, 2048, []jose.KeyOps{jose.KeyOpsSign})
	require.NoError(t, err)
	verificationKey, err := signingKey.Verifier()
	require.NoError(t, err)
	jwk, err := verificationKey.Jwk()
	require.NoError(t, err)

	signer := NewJwtSigner("issuer", signingKey)
	ks, err := NewTrustKeyStore(map[string]jose.Jwk{signer.Issuer(): jwk})
	require.NoError(t, err)
	verifier := NewJwtVerifier(ks)

	claims := jose.SettableJwtClaims{
		Audiences: jose.Audiences{Aud: []string{"audience"}},
		Subject:   "subject",
	}
	token, err := signer.Sign(&claims, map[string]interface{}{})
	require.NoError(t, err)

	_, _, err = verifier.Verify(token, []string{"audience"})
	assert.ErrorIs(t, err, ErrInvalidJwtTimeframe,
		"a token with no exp must not be accepted as non-expiring")
}

// M-G17: with an externally-generated IV the encryptor trims the nonce the backend
// appended to the tag. A backend returning a tag shorter than the nonce made the slice
// expressions panic; the length is now checked first.
func TestJweDirectEncryptorAeadRejectsShortTag(t *testing.T) {
	keyMock := &authenticatedEncryptionKeyMock{}
	keyMock.On("Kid").Return("unique")
	keyMock.On("Algorithm").Return(jose.AlgA256GCM)
	keyMock.On("GenerateNonce").Return(make([]byte, 12), nil)
	// Tag shorter than the 12-byte nonce the backend claims to have appended.
	keyMock.On("Seal", jose.KeyOpsEncrypt, mock.Anything, mock.Anything, mock.Anything).
		Return([]byte("ciphertext"), []byte("short"), nil)

	encryptor := NewJweDirectEncryptorAead(keyMock, true)
	_, err := encryptor.Encrypt([]byte("plaintext"), nil)
	assert.ErrorIs(t, err, ErrInvalidAuthenticationTag)
}

// M-G18: PublicFromPrivate copied the "x"/"y" members of a private EC JWK instead of
// deriving the public point from "d". A JWK whose "x"/"y" disagree with "d" therefore
// produced a public key unrelated to the private key it came from.
func TestPublicFromPrivateDerivesEcPointFromD(t *testing.T) {
	curve := elliptic.P256()
	d, err := rand.Int(rand.Reader, curve.Params().N)
	require.NoError(t, err)
	expectedX, expectedY := curve.ScalarBaseMult(d.Bytes())

	priv := &jose.PrivateEcKey{}
	priv.Crv = jose.CrvP256
	priv.D.Set(d)
	// Deliberately inconsistent public point.
	priv.X.Set(big.NewInt(1))
	priv.Y.Set(big.NewInt(2))
	priv.SetAlg(jose.AlgES256)
	priv.SetKid("k1")
	priv.SetOps([]jose.KeyOps{jose.KeyOpsSign})

	pub, err := PublicFromPrivate(priv)
	require.NoError(t, err)
	pubEc, ok := pub.(*jose.PublicEcKey)
	require.True(t, ok, "expected a public EC key")
	assert.Zero(t, pubEc.X.Int().Cmp(expectedX), "X must be derived from d")
	assert.Zero(t, pubEc.Y.Int().Cmp(expectedY), "Y must be derived from d")
	assert.Equal(t, jose.CrvP256, pubEc.Crv)
}

// The derived public key must actually verify a signature made by the private key.
func TestPublicFromPrivateDerivedKeyVerifies(t *testing.T) {
	curve := elliptic.P256()
	d, err := rand.Int(rand.Reader, curve.Params().N)
	require.NoError(t, err)
	x, y := curve.ScalarBaseMult(d.Bytes())

	priv := &jose.PrivateEcKey{}
	priv.Crv = jose.CrvP256
	priv.D.Set(d)
	priv.X.Set(big.NewInt(1))
	priv.Y.Set(big.NewInt(2))
	priv.SetAlg(jose.AlgES256)
	priv.SetKid("k1")
	priv.SetOps([]jose.KeyOps{jose.KeyOpsSign})

	pub, err := PublicFromPrivate(priv)
	require.NoError(t, err)
	pubEc, ok := pub.(*jose.PublicEcKey)
	require.True(t, ok)

	ecKey := &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{Curve: curve, X: x, Y: y},
		D:         d,
	}
	data := []byte("data to be signed")
	digest := sha256.Sum256(data)
	r, s, err := ecdsa.Sign(rand.Reader, ecKey, digest[:])
	require.NoError(t, err)
	// The verifier expects the JWS raw r||s encoding, each padded to the curve size.
	keySize := (curve.Params().BitSize + 7) / 8
	sig := make([]byte, 2*keySize)
	r.FillBytes(sig[:keySize])
	s.FillBytes(sig[keySize:])

	verifier, err := NewVerificationKey(pubEc)
	require.NoError(t, err)
	assert.True(t, verifier.Verify(jose.KeyOpsVerify, data, sig))
}
