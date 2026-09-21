// SPDX-FileCopyrightText: 2026 Thales Group and the gose Contributors
// SPDX-License-Identifier: MIT

// Package hsm provides asymmetric decryption keys backed by a Hardware Security Module.
package hsm

import (
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"log/slog"

	"github.com/eclipse-keypont/crypto11/v2"

	"github.com/eclipse-keypont/gose"
	"github.com/eclipse-keypont/gose/jose"
)

// AsymmetricDecryptionKey implements RSAES-OAEP decryption. The digest is chosen per
// operation by the hash passed to Decrypt, so the same key serves both the SHA-1
// ("RSA-OAEP") and SHA-256 ("RSA-OAEP-256") variants, subject to what the token supports.
// This structure is made to provide a management of pkcs11-handled asymmetric key pairs
type AsymmetricDecryptionKey struct {
	kid      []byte
	keylabel []byte
	ctx      *crypto11.Context
	key      crypto11.SignerDecrypter
}

// Kid the unique identifier of this key.
func (a *AsymmetricDecryptionKey) Kid() string {
	return string(a.kid)
}

// Certificates associated x509 certificates.
func (a *AsymmetricDecryptionKey) Certificates() []*x509.Certificate {
	// TODO: lookup certificates
	cert, err := a.ctx.FindCertificate(a.kid, a.keylabel, nil)
	if err != nil {
		// TODO: return an error via an interface signature change in next major version.
		slog.Error("failed to find certificate for HSM key", "kid", string(a.kid), "err", err)
		return nil
	}
	return []*x509.Certificate{cert}
}

// Algorithm returns jose.AlgRSAOAEP, naming the RSAES-OAEP family this key implements.
// The JWE protected header, not this value, determines which OAEP digest a given
// ciphertext uses.
func (a *AsymmetricDecryptionKey) Algorithm() jose.Alg {
	return jose.AlgRSAOAEP
}

// Decrypt the given ciphertext data returning the derived plaintext.
func (a *AsymmetricDecryptionKey) Decrypt(_ jose.KeyOps, hash crypto.Hash, bytes []byte) ([]byte, error) {
	randReader, err := a.ctx.NewRandomReader()
	if err != nil {
		return nil, err
	}

	return a.key.Decrypt(randReader, bytes, &rsa.OAEPOptions{
		Hash:  hash,
		Label: nil,
	})
}

// Encryptor get the matching AsymmetricEncryptionKey for this decryptor.
func (a *AsymmetricDecryptionKey) Encryptor() (gose.AsymmetricEncryptionKey, error) {
	jwk, err := gose.JwkFromPublicKey(a.key.Public(), []jose.KeyOps{jose.KeyOpsEncrypt}, a.Certificates())
	if err != nil {
		return nil, err
	}
	return gose.NewRsaPublicKeyImpl(jwk)
}

var _ gose.AsymmetricDecryptionKey = (*AsymmetricDecryptionKey)(nil)

// NewAsymmetricDecryptionKey creates an instance with the given pkcs11
// key handler.
// 'keyid' or 'keylabel' can be nil, but nut both. Provide at least one or both.
func NewAsymmetricDecryptionKey(pkcs11Context *crypto11.Context, key crypto11.SignerDecrypter, kid []byte, keylabel []byte) (*AsymmetricDecryptionKey, error) {
	return &AsymmetricDecryptionKey{
		kid:      kid,
		keylabel: keylabel,
		ctx:      pkcs11Context,
		key:      key,
	}, nil
}
