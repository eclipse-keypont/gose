// SPDX-FileCopyrightText: 2026 Thales Group and the gose Contributors
// SPDX-License-Identifier: MIT

package gose

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/eclipse-keypont/gose/jose"
)

// reserialiseHeader decodes a BASE64URL protected header, applies edit to its members,
// and re-encodes it the way a foreign producer might: encoding/json sorts map keys, so
// the member order differs from gose's struct order, and the extra member is one gose
// does not model.
func reserialiseHeader(t *testing.T, b64 string, edit func(m map[string]json.RawMessage)) string {
	t.Helper()
	raw, err := base64.RawURLEncoding.DecodeString(b64)
	require.NoError(t, err)
	m := map[string]json.RawMessage{}
	require.NoError(t, json.Unmarshal(raw, &m))
	edit(m)
	out, err := json.Marshal(m)
	require.NoError(t, err)
	require.NotEqual(t, string(raw), string(out), "the re-serialisation must actually differ from gose's own")
	return base64.RawURLEncoding.EncodeToString(out)
}

// TestJweDirectDecryptorBlock_AadIsReceivedHeader pins RFC 7516 §5.2 step 14 for the
// AES-CBC/HMAC path: the AAD is the protected header as received. A JWE whose header
// a foreign producer serialised differently — members reordered, plus one gose does
// not model — but authenticated correctly must decrypt; before the fix the verifier
// re-marshalled the parsed header, dropped the unknown member, and rejected it as
// "integrity check failed". Tampering with the received header must still be caught.
func TestJweDirectDecryptorBlock_AadIsReceivedHeader(t *testing.T) {
	key := make([]byte, 32)
	_, err := rand.Read(key)
	require.NoError(t, err)
	iv := make([]byte, aes.BlockSize)
	_, err = rand.Read(iv)
	require.NoError(t, err)
	block, err := aes.NewCipher(key)
	require.NoError(t, err)
	hk := NewHmacShaCryptor("hmac0", sha256.New())
	newDecryptor := func() *JweDirectDecryptorBlock {
		return NewJweDirectDecryptorBlock(NewAesCbcCryptor(cipher.NewCBCDecrypter(block, iv), "aes0", jose.AlgA256CBC), hk)
	}

	plaintext := []byte("received bytes are the AAD")
	encryptor := NewJweDirectEncryptorBlock(NewAesCbcCryptor(cipher.NewCBCEncrypter(block, iv), "aes0", jose.AlgA256CBC), hk, iv)
	produced, err := encryptor.Encrypt(plaintext, nil)
	require.NoError(t, err)
	parts := strings.Split(produced, ".")
	require.Len(t, parts, 5)

	// Same content, foreign serialisation, tag recomputed over the bytes actually sent.
	foreignHeader := reserialiseHeader(t, parts[0], func(m map[string]json.RawMessage) {
		m["x-foreign-member"] = json.RawMessage(`"opaque"`)
	})
	ciphertext, err := base64.RawURLEncoding.DecodeString(parts[3])
	require.NoError(t, err)
	tag := NewJweHmacVerifier(hk).ComputeHash([]byte(foreignHeader), iv, ciphertext)
	foreign := strings.Join([]string{foreignHeader, parts[1], parts[2], parts[3], base64.RawURLEncoding.EncodeToString(tag)}, ".")

	got, _, err := newDecryptor().Decrypt(foreign)
	require.NoError(t, err)
	require.Equal(t, plaintext, got)

	// A header altered after the tag was computed is rejected, unknown member or not.
	tamperedHeader := reserialiseHeader(t, parts[0], func(m map[string]json.RawMessage) {
		m["x-foreign-member"] = json.RawMessage(`"opaque"`)
		m["kid"] = json.RawMessage(`"aes0"`) // unchanged value...
		m["typ"] = json.RawMessage(`"JOSE"`) // ...but this one changes
	})
	tampered := strings.Join([]string{tamperedHeader, parts[1], parts[2], parts[3], base64.RawURLEncoding.EncodeToString(tag)}, ".")
	_, _, err = newDecryptor().Decrypt(tampered)
	require.ErrorContains(t, err, "integrity check failed")

	// gose's own output still round-trips.
	got, _, err = newDecryptor().Decrypt(produced)
	require.NoError(t, err)
	require.Equal(t, plaintext, got)
}

// TestJweRsaKeyEncryptionDecryptorImpl_AadIsReceivedHeader pins the same rule for the
// RSA-OAEP key-encryption path, using RFC 7516 Appendix A.1: its CEK and IV are
// published, so the header can be re-serialised in a different member order and the
// GCM tag recomputed over the new AAD while the wrapped CEK stays byte-for-byte the
// spec's. gose's re-marshalled header happens to match the spec's {"alg","enc"} order,
// which is why the KAT passed before; {"enc","alg"} did not.
func TestJweRsaKeyEncryptionDecryptorImpl_AadIsReceivedHeader(t *testing.T) {
	// RFC 7516 §A.1.2 CEK and §A.1.4 IV.
	cek := []byte{177, 161, 244, 128, 84, 143, 225, 115, 63, 180, 3, 255, 107, 154, 212, 246, 138, 7, 110, 91, 112, 46, 34, 105, 47, 130, 203, 46, 122, 234, 64, 252}
	iv := []byte{227, 197, 117, 252, 2, 219, 233, 68, 180, 225, 77, 219}
	plaintext := []byte("The true sign of intelligence is not knowledge but imagination.")

	parts := strings.Split(oaepJweFromSpec, ".")
	require.Len(t, parts, 5)
	// {"alg":"RSA-OAEP","enc":"A256GCM"} → {"enc":"A256GCM","alg":"RSA-OAEP"}: same
	// members, different order — encoding/json sorts map keys, so build it by hand.
	foreignHeader := base64.RawURLEncoding.EncodeToString([]byte(`{"enc":"A256GCM","alg":"RSA-OAEP"}`))
	require.NotEqual(t, parts[0], foreignHeader)

	block, err := aes.NewCipher(cek)
	require.NoError(t, err)
	gcm, err := cipher.NewGCM(block)
	require.NoError(t, err)
	sealed := gcm.Seal(nil, iv, plaintext, []byte(foreignHeader))
	ciphertext, tag := sealed[:len(plaintext)], sealed[len(plaintext):]

	foreign := strings.Join([]string{
		foreignHeader,
		parts[1], // the spec's wrapped CEK, unchanged
		base64.RawURLEncoding.EncodeToString(iv),
		base64.RawURLEncoding.EncodeToString(ciphertext),
		base64.RawURLEncoding.EncodeToString(tag),
	}, ".")

	got, _, err := generateDecryptor(t).Decrypt(foreign, crypto.Hash(0))
	require.NoError(t, err)
	require.Equal(t, plaintext, got)
}
