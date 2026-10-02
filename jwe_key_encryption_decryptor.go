// SPDX-FileCopyrightText: 2026 Thales Group and the gose Contributors
// SPDX-License-Identifier: MIT

package gose

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"slices"

	"github.com/eclipse-keypont/gose/jose"
)

var supportedEncryptionAlgs = []jose.Enc{jose.EncA256GCM, jose.EncA128GCM, jose.EncA192GCM}

// JweRsaKeyEncryptionDecryptorImpl implements RSA Key Encryption CEK mode.
type JweRsaKeyEncryptionDecryptorImpl struct {
	keystore AsymmetricDecryptionKeyStore
}

// Decrypt decrypts the given JWE returning the contained plaintext and any additional authentic
// associated data.
// This method follow recommendations of https://datatracker.ietf.org/doc/html/rfc7516#section-5.2
//
// Pass crypto.Hash(0) as oaepHash to derive the OAEP digest from the "alg" header, which is
// what RFC 7518 §4.3 requires and what every conformant producer allows: "RSA-OAEP" means
// SHA-1 and "RSA-OAEP-256" means SHA-256.
//
// A non-zero oaepHash overrides the header. This exists only to read JWEs written by gose
// before it labelled the SHA-256 variant correctly, which carry "RSA-OAEP" in the header
// but wrap the CEK with SHA-256; such JWEs are not portable to other implementations.
// Do not use the override for newly produced JWEs.
func (d *JweRsaKeyEncryptionDecryptorImpl) Decrypt(jweRaw string, oaepHash crypto.Hash) (plaintext, aad []byte, err error) {
	// deserialize jwe
	var jwe jose.JweRfc7516Compact
	if err = jwe.Unmarshal(jweRaw); err != nil {
		return nil, nil, fmt.Errorf("error unmarshalling the jwe: %w", err)
	}

	// We do not support zip compression
	if jwe.ProtectedHeader.Zip != "" {
		err = ErrZipCompressionNotSupported
		return
	}

	// check CEK encryption is supported
	if !slices.Contains(supportedEncryptionAlgs, jwe.ProtectedHeader.Enc) {
		return nil, nil, ErrInvalidEncryption
	}

	// load key from keystore info before CEK decryption
	var key AsymmetricDecryptionKey
	key, err = d.keystore.Get(jwe.ProtectedHeader.Kid)
	if err != nil {
		return nil, nil, fmt.Errorf("error getting key from keystore: %w", err)
	}

	// Check alg is as expected. The header names one of the two RSAES-OAEP variants while
	// the key names the family, so compare on the family and take the digest from the header.
	headerHash, headerIsOaep := OaepHashFromAlg(jwe.ProtectedHeader.Alg)
	if !headerIsOaep || !isRsaOaepAlg(key.Algorithm()) {
		return nil, nil, ErrInvalidAlgorithm
	}

	// RFC 7518 §4.3 binds the digest to the header; a caller-supplied digest overrides it
	// only to read legacy gose JWEs that advertise "RSA-OAEP" but were wrapped with SHA-256.
	if oaepHash == crypto.Hash(0) {
		oaepHash = headerHash
	}

	// Decrypt CEK
	var cek []byte
	if cek, err = key.Decrypt(jose.KeyOpsDecrypt, oaepHash, jwe.EncryptedKey); err != nil {
		return
	}
	// The decrypted content-encryption key must not linger in the heap.
	defer clear(cek)

	// decrypt cipher text with cek
	var block cipher.Block
	if block, err = aes.NewCipher(cek); err != nil {
		return nil, nil, fmt.Errorf("error creating AES cipher: %w", err)
	}
	var aead cipher.AEAD
	if aead, err = cipher.NewGCM(block); err != nil {
		return nil, nil, fmt.Errorf("error creating GCM AEAD: %w", err)
	}
	// The IV and tag are attacker-controlled: producing a valid EncryptedKey needs only
	// the recipient's public key, so this point is reachable without any secret. GCM.Open
	// panics on a wrong-sized nonce, so both lengths are checked before we reach it.
	if len(jwe.InitializationVector) != aead.NonceSize() {
		return nil, nil, ErrInvalidNonce
	}
	if len(jwe.AuthenticationTag) != aead.Overhead() {
		return nil, nil, ErrInvalidAuthenticationTag
	}
	// concatenate ciphertext and tag for authenticated decryption
	// [ciphertext + tag] is the result of the encryption and needs to be provided for decryption
	ctAndTag := make([]byte, len(jwe.Ciphertext)+len(jwe.AuthenticationTag))
	copy(ctAndTag[:len(jwe.Ciphertext)], jwe.Ciphertext)
	copy(ctAndTag[len(jwe.Ciphertext):], jwe.AuthenticationTag)
	// retrieve aad
	if aad, err = jwe.ProtectedHeader.MarshalProtectedHeader(); err != nil {
		return nil, nil, fmt.Errorf("error getting AAD: %w", err)
	}
	plaintext, err = aead.Open(nil, jwe.InitializationVector, ctAndTag, aad)
	if err != nil {
		return
	}

	return
}

// NewJweRsaKeyEncryptionDecryptorImpl creates an instance of JweRsaKeyEncryptionDecryptorImpl with the given keystore.
func NewJweRsaKeyEncryptionDecryptorImpl(keystore AsymmetricDecryptionKeyStore) *JweRsaKeyEncryptionDecryptorImpl {
	return &JweRsaKeyEncryptionDecryptorImpl{
		keystore: keystore,
	}
}
