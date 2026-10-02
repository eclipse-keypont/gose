// SPDX-FileCopyrightText: 2026 Thales Group and the gose Contributors
// SPDX-License-Identifier: MIT

package gose

import (
	"crypto/cipher"
	"crypto/rand"
	"io"

	"github.com/eclipse-keypont/gose/jose"
)

var validEncryptionOpts = []jose.KeyOps{jose.KeyOpsEncrypt}
var validDecryptionOpts = []jose.KeyOps{jose.KeyOpsDecrypt}
var validCryptorOpts = []jose.KeyOps{jose.KeyOpsEncrypt, jose.KeyOpsDecrypt}

// AesGcmCryptor provides AES GCM encryption and decryption functions.
type AesGcmCryptor struct {
	kid  string
	alg  jose.Alg
	aead cipher.AEAD
	opts []jose.KeyOps
	rng  io.Reader
}

// Kid the key identity
func (cryptor *AesGcmCryptor) Kid() string {
	return cryptor.kid
}

// Algorithm the supported algorithm
func (cryptor *AesGcmCryptor) Algorithm() jose.Alg {
	return cryptor.alg
}

// GenerateNonce generate a nonce of the correct size for use with GCM encryption/decryption from a random source.
func (cryptor *AesGcmCryptor) GenerateNonce() ([]byte, error) {
	nonce := make([]byte, cryptor.aead.NonceSize())
	if _, err := io.ReadFull(cryptor.rng, nonce); err != nil {
		return nil, err
	}
	return nonce, nil
}

// Open decrypt a previously encrypted ciphertext.
func (cryptor *AesGcmCryptor) Open(operation jose.KeyOps, nonce, ciphertext, aad, tag []byte) (plaintext []byte, err error) {
	ops := intersection(validDecryptionOpts, cryptor.opts)
	if !isSubset(ops, []jose.KeyOps{operation}) {
		err = ErrInvalidOperations
		return
	}
	// The nonce comes straight off the wire on the decryption path. cipher.AEAD.Open
	// panics rather than erroring on a wrong-sized nonce, so check it here as Seal does.
	if len(nonce) != cryptor.aead.NonceSize() {
		err = ErrInvalidNonce
		return
	}
	// Likewise the tag: a wrong-sized tag cannot authenticate, and rejecting it here
	// gives the caller a precise error instead of an opaque authentication failure.
	if len(tag) != cryptor.aead.Overhead() {
		err = ErrInvalidAuthenticationTag
		return
	}
	dst := make([]byte, 0, len(ciphertext))
	ciphertextAndTag := make([]byte, len(ciphertext)+len(tag))
	_ = copy(ciphertextAndTag, ciphertext)
	_ = copy(ciphertextAndTag[len(ciphertext):], tag)
	if dst, err = cryptor.aead.Open(dst, nonce, ciphertextAndTag, aad); err != nil {
		return
	}
	plaintext = dst
	return
}

// Seal encrypt a supplied plaintext and AAD.
func (cryptor *AesGcmCryptor) Seal(operation jose.KeyOps, nonce, plaintext, aad []byte) (ciphertext, tag []byte, err error) {
	ops := intersection(validEncryptionOpts, cryptor.opts)
	if !isSubset(ops, []jose.KeyOps{operation}) {
		err = ErrInvalidOperations
		return
	}
	// If a nil nonce provided, this is interpreted as the encryptor providing the nonce
	if nil != nonce && len(nonce) != cryptor.aead.NonceSize() {
		err = ErrInvalidNonce
		return
	}
	sz := cryptor.aead.Overhead() + len(plaintext)
	// If a nil nonce provided, allocate extra capacity for the nonce to be returned
	if nil == nonce {
		sz += cryptor.aead.NonceSize()
	}
	dst := make([]byte, 0, sz)
	dst = cryptor.aead.Seal(dst, nonce, plaintext, aad)
	ciphertext = dst[:len(plaintext)]
	// If the HSM is supplying the IV appended to the end, we return this contained in the tag and extract later
	tag = dst[len(plaintext):]
	return
}

// NewAesGcmCryptorFromJwk create a new instance of an AesGCmCryptor from a JWK.
func NewAesGcmCryptorFromJwk(jwk jose.Jwk, required []jose.KeyOps) (AeadEncryptionKey, error) {
	/* Check jwk can be used to encrypt or decrypt */
	ops := intersection(validCryptorOpts, jwk.Ops())
	if len(ops) == 0 {
		return nil, ErrInvalidOperations
	}
	/* Load the jwk */
	aead, err := LoadSymmetricAEAD(jwk, required)
	if err != nil {
		return nil, err
	}
	return &AesGcmCryptor{
		kid:  jwk.Kid(),
		alg:  jwk.Alg(),
		aead: aead,
		rng:  rand.Reader,
		opts: jwk.Ops(),
	}, nil
}

// NewAesGcmCryptor create a new instance of an AesGCmCryptor from the supplied parameters.
func NewAesGcmCryptor(aead cipher.AEAD, rng io.Reader, kid string, alg jose.Alg, operations []jose.KeyOps) (AeadEncryptionKey, error) {
	return &AesGcmCryptor{
		kid:  kid,
		alg:  alg,
		aead: aead,
		rng:  rng,
		opts: operations,
	}, nil
}
