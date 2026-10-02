// SPDX-FileCopyrightText: 2026 Thales Group and the gose Contributors
// SPDX-License-Identifier: MIT

// Package gose implements JOSE (JWT, JWK, JWS, JWE, JWKS) primitives and helpers for Go.
package gose

import (
	"context"
	"crypto"
	"crypto/x509"
	"fmt"

	"github.com/eclipse-keypont/gose/jose"
)

// InvalidFormat is an interface for handling invalid format errors
type InvalidFormat struct {
	what string
}

func (err *InvalidFormat) Error() string {
	return fmt.Sprintf("Invalid format: %s", err.what)
}

// Algorithmed is an interface that exposes which algorithm a type can be used
// with.
type Algorithmed interface {
	Algorithm() jose.Alg
}

// Key is an interface representing a cryptographic key.
type Key interface {
	// Kid returns the identity of the key.
	Kid() string
}

// MarshalableKey is an interface representing a key that can be marshaled into a JWK.
type MarshalableKey interface {
	// Jwk returns the Key as a JSON Web Key.
	Jwk() (jose.Jwk, error)
	// Marshal marshals a key to it's compact JWK string representation.
	Marshal() (string, error)
}

// CertifiableKey is an interface representing a key that can have an associated certificate and PEM representation.
type CertifiableKey interface {
	// MarshalPem marshals a key to it's PEM representation.
	MarshalPem() (string, error)
	// Certificates returns the certificate chain for the given key.
	Certificates() []*x509.Certificate
}

// SigningKey interface implementers both digest and signing of data.
type SigningKey interface {
	Key
	MarshalableKey
	CertifiableKey
	Algorithmed
	// Key returns the underlying key used to sign
	Key() crypto.Signer
	// Sign digest and sign the given data.
	Sign(jose.KeyOps, []byte) ([]byte, error)
	// Verifier get the matching verification key.
	Verifier() (VerificationKey, error)
}

// VerificationKey implements verification of a cryptographic signature.
type VerificationKey interface {
	Key
	MarshalableKey
	CertifiableKey
	Algorithmed
	// Verify verifies the operation being performed is supported and
	// that the signature is derived from the data.
	Verify(operation jose.KeyOps, data []byte, signature []byte) bool
}

// AsymmetricEncryptionKey implements encryption using an asymmetric key.
type AsymmetricEncryptionKey interface {
	Key
	MarshalableKey
	CertifiableKey
	Algorithmed
	Encrypt(ops jose.KeyOps, hash crypto.Hash, bytes []byte) ([]byte, error)
}

// AsymmetricDecryptionKey provides asymmetric decryption (private key) capabilities.
type AsymmetricDecryptionKey interface {
	Key
	Algorithmed
	Decrypt(ops jose.KeyOps, hash crypto.Hash, bytes []byte) ([]byte, error)
	// Encryptor get the matching encryption key.
	Encryptor() (AsymmetricEncryptionKey, error)
}

// AeadEncryptionKey implements authenticated encryption and decryption.
type AeadEncryptionKey interface {
	Key
	Algorithmed
	// GenerateNonce generates a nonce of the correct size for use in Sealinging operations.
	GenerateNonce() ([]byte, error)
	// Seal the given plaintext returning ciphertext and authentication tag.
	Seal(operation jose.KeyOps, nonce, plaintext, aad []byte) (ciphertext, tag []byte, err error)
	// Open and validate the given ciphertext and tag returning the plaintext.
	Open(operation jose.KeyOps, nonce, ciphertext, aad, tag []byte) (plaintext []byte, err error)
}

// BlockEncryptionKey implements encryption and decryption operations with block modes and symmetric keys
type BlockEncryptionKey interface {
	Key
	Algorithmed
	// Seal the given plaintext returning ciphertext
	Seal(plaintext []byte) []byte
	// Open and validate the given ciphertext
	Open(ciphertext []byte) []byte
}

// HmacKey implements keyed-hash message authentication code operations.
type HmacKey interface {
	Key
	// Hash method gets bytes as input and sum it all to return a hashed result in a 32 bytes array
	Hash(input []byte) []byte
}

// JwtSigner implements generation of signed compact JWTs as defined by https://tools.ietf.org/html/rfc7519.
type JwtSigner interface {
	// Issuer returns the identity of the issuing authority
	Issuer() string
	// Sign signs a set of claims returning a serialized JWT.
	Sign(claims *jose.SettableJwtClaims, untyped map[string]interface{}) (string, error)
}

// JwtVerifier implements verification of signed compact JWTs as defined by https://tools.ietf.org/html/rfc7519.
type JwtVerifier interface {
	// Verify verifies a JWT is a valid jwt where the caller can specify a number of allowable audiences.
	Verify(jwt string, audience []string) (kid string, claims *jose.JwtClaims, err error)
}

// TrustStore provides the ability to manage trusted root public keys for use when verifying cryptographic
// signatures.
type TrustStore interface {
	Add(issuer string, jwk jose.Jwk) error
	Remove(issuer, kid string) bool
	Get(ctx context.Context, issuer, kid string) (vk VerificationKey, err error)
}

// AsymmetricDecryptionKeyStore provides the ability to access asymmetric decryption keys.
type AsymmetricDecryptionKeyStore interface {
	Get(kid string) (k AsymmetricDecryptionKey, err error)
}

// JweEncryptor implements encryption of arbitrary plaintext into a compact JWE as defined by https://tools.ietf.org/html/rfc7516.
type JweEncryptor interface {
	Encrypt(plaintext, aad []byte) (string, error)
}

// JweDecryptor implements decryption and verification of a given ciphertext and aad to a plaintext as defined by https://tools.ietf.org/html/rfc7516.
type JweDecryptor interface {
	Decrypt(jwe string) (plaintext, aad []byte, err error)
}

// JweHmacVerifier implements HMAC-based authentication tag computation and verification for a compact JWE.
type JweHmacVerifier interface {
	// ComputeHash computes the authentication Tag for of a Jwe by hashing the concatenated values in argument
	//  aad is the protected header of the JWE encoded in b64
	//  IV is the initialization vector of the JWE recipient for the encryption/decryption operations
	//  Ciphertext is the result of the encryption operation using the current IV
	//  AL is representing the number of bits (length) in AAD expressed as a big-endian 64-bit unsigned integer
	// Returns the hash result of a hmac operation given the concatenated slice of the values above
	ComputeHash(aad []byte, iv []byte, ciphertext []byte) []byte
	// VerifyCompact a compact jwe (rfc 7516) in input and computes its authentication TAG with a hmac operation with
	// the authentication TAG in the JWE.
	// Returns false if the integrity check fails, i.e the tags are different
	VerifyCompact(jwe jose.JweRfc7516Compact) (result bool, err error)
}
