// SPDX-FileCopyrightText: 2026 Thales Group and the gose Contributors
// SPDX-License-Identifier: MIT

package gose

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"log/slog"
	"math/big"

	"github.com/eclipse-keypont/gose/jose"
)

// RsaPrivateKeyImpl provides software based signing and decryption capabilities for use during JWT and JWE processing.
type RsaPrivateKeyImpl struct {
	jwk jose.Jwk
	key *rsa.PrivateKey
	// ops and alg are captured at construction; see SigningKeyImpl for why.
	ops []jose.KeyOps
	alg jose.Alg
}

// Key returns the underlying crypto.Signer implementation.
func (rsaKey *RsaPrivateKeyImpl) Key() crypto.Signer {
	return rsaKey.key
}

// Operations returns the allowed operations for the SigningKey
func (rsaKey *RsaPrivateKeyImpl) Operations() []jose.KeyOps {
	return cloneOps(rsaKey.ops)
}

// Kid returns the jwk id
func (rsaKey *RsaPrivateKeyImpl) Kid() string {
	/* JIT jwk load. */
	return rsaKey.jwk.Kid()
}

// Jwk returns the JWK
func (rsaKey *RsaPrivateKeyImpl) Jwk() (jose.Jwk, error) {
	return rsaKey.jwk, nil
}

// Algorithm returns the Algorithm
func (rsaKey *RsaPrivateKeyImpl) Algorithm() jose.Alg {
	return rsaKey.alg
}

// Marshal marshal the key to a JWK string, or error
func (rsaKey *RsaPrivateKeyImpl) Marshal() (string, error) {
	return JwkToString(rsaKey.jwk)
}

// MarshalPem marshal the key to a PEM string, or error
func (rsaKey *RsaPrivateKeyImpl) MarshalPem() (string, error) {
	var pemType string
	var derEncoded []byte
	pemType = rsaPrivateKeyPemType
	derEncoded = x509.MarshalPKCS1PrivateKey(rsaKey.key)
	block := pem.Block{
		Type:  pemType,
		Bytes: derEncoded,
	}
	output := bytes.Buffer{}
	if err := pem.Encode(&output, &block); err != nil {
		return "", err
	}
	return output.String(), nil
}

// Sign perform signing operations on data, or error
func (rsaKey *RsaPrivateKeyImpl) Sign(requested jose.KeyOps, data []byte) ([]byte, error) {
	/* Verify the operation being requested is supported by the captured policy. */
	ops := intersection(validSignerOps, rsaKey.ops)
	if !isSubset(ops, []jose.KeyOps{requested}) {
		return nil, ErrInvalidOperations
	}
	// A decryption key is labelled RSA-OAEP, which has no signing options: refuse
	// rather than dereference a nil entry.
	opts, err := signerOptsForAlg(rsaKey.alg)
	if err != nil {
		return nil, err
	}
	/* Calculate digest. */
	digester := opts.HashFunc().New()
	if _, err := digester.Write(data); err != nil {
		slog.Error("hash write error", "err", err)
		return nil, err
	}
	digest := digester.Sum(nil)
	return rsaKey.key.Sign(rand.Reader, digest, opts)
}

// Certificates of signing key
func (rsaKey *RsaPrivateKeyImpl) Certificates() []*x509.Certificate {
	return rsaKey.jwk.X5C()
}

// Decrypt decrypt the given ciphertext returning the derived plaintext.
func (rsaKey *RsaPrivateKeyImpl) Decrypt(requested jose.KeyOps, hash crypto.Hash, ciphertext []byte) ([]byte, error) {
	ops := intersection(validDecryptionOps, rsaKey.ops)
	if !isSubset(ops, []jose.KeyOps{requested}) {
		return nil, ErrInvalidOperations
	}
	// SHA1 is still safe when used in the construction of OAEP.
	return rsa.DecryptOAEP(hash.New(), rand.Reader, rsaKey.key, ciphertext, nil)
}

func (rsaKey *RsaPrivateKeyImpl) publicKey() (*RsaPublicKeyImpl, error) {
	publicJwk, err := PublicFromPrivate(rsaKey.jwk)
	if err != nil {
		return nil, err
	}
	// Clone the modulus: rsa.PublicKey is a struct copy but N is a *big.Int shared with
	// the private key, so handing it out by reference would let a later mutation of one
	// change the other (CWE-347).
	pub := rsaKey.key.PublicKey
	pub.N = new(big.Int).Set(rsaKey.key.N)
	// The public JWK carries the inverted operations (decrypt -> encrypt, sign -> verify),
	// so capture those rather than the private key's own policy.
	return &RsaPublicKeyImpl{
		key: pub,
		jwk: publicJwk,
		ops: cloneOps(publicJwk.Ops()),
		alg: publicJwk.Alg(),
	}, nil
}

// Verifier verification key for signing jwk
func (rsaKey *RsaPrivateKeyImpl) Verifier() (VerificationKey, error) {
	return rsaKey.publicKey()
}

// Encryptor get encryption key
func (rsaKey *RsaPrivateKeyImpl) Encryptor() (AsymmetricEncryptionKey, error) {
	return rsaKey.publicKey()
}

// NewRsaDecryptionKey returns a new instance of RsaPrivateKeyImpl configured using he given JWK.
func NewRsaDecryptionKey(jwk jose.Jwk) (*RsaPrivateKeyImpl, error) {
	signer, err := LoadPrivateKey(jwk, []jose.KeyOps{jose.KeyOpsDecrypt})
	if err != nil {
		return nil, err
	}
	rsaKey, ok := signer.(*rsa.PrivateKey)
	if !ok {
		return nil, ErrInvalidKeyType
	}
	return &RsaPrivateKeyImpl{
		jwk: jwk,
		key: rsaKey,
		ops: cloneOps(jwk.Ops()),
		alg: jwk.Alg(),
	}, nil
}
