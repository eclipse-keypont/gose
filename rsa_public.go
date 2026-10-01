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

	"github.com/eclipse-keypont/gose/jose"
)

// RsaPublicKeyImpl implements RSA verification and encryption APIs
type RsaPublicKeyImpl struct {
	key rsa.PublicKey
	jwk jose.Jwk
	// ops and alg capture the authorization policy and algorithm at construction
	// time so later mutation of the source JWK cannot alter this key's behaviour
	// (M-G2/M-G3).
	ops []jose.KeyOps
	alg jose.Alg
}

const rsaPublicKeyPemType = "RSA PUBLIC KEY"

var (
	pssAlgs = map[jose.Alg]bool{
		jose.AlgPS256: true,
		jose.AlgPS384: true,
		jose.AlgPS512: true,
	}
)

// Kid returns the key's id
func (k *RsaPublicKeyImpl) Kid() string {
	return k.jwk.Kid()
}

// Algorithm returns algorithm
func (k *RsaPublicKeyImpl) Algorithm() jose.Alg {
	return k.alg
}

// Jwk returns the public JWK
func (k *RsaPublicKeyImpl) Jwk() (jose.Jwk, error) {
	jwk, err := JwkFromPublicKey(&k.key, cloneOps(k.ops), k.jwk.X5C())
	if err != nil {
		return nil, err
	}
	jwk.SetAlg(k.alg)
	return jwk, nil
}

// Marshal returns the key marshalled to a JWK string, or error
func (k *RsaPublicKeyImpl) Marshal() (string, error) {
	jwk, err := k.Jwk()
	if err != nil {
		return "", err
	}
	return JwkToString(jwk)
}

// MarshalPem returns the key marshalled to a PEM string, or error
func (k *RsaPublicKeyImpl) MarshalPem() (string, error) {
	derEncoded, err := x509.MarshalPKIXPublicKey(&k.key)
	if err != nil {
		return "", err
	}

	block := pem.Block{
		Type:  rsaPublicKeyPemType,
		Bytes: derEncoded,
	}
	output := bytes.Buffer{}
	if err := pem.Encode(&output, &block); err != nil {
		return "", err
	}
	return output.String(), nil
}

// Verify data matches signature
func (k *RsaPublicKeyImpl) Verify(operation jose.KeyOps, data []byte, signature []byte) bool {
	ops := intersection(validVerificationOps, k.ops)
	if !isSubset(ops, []jose.KeyOps{operation}) {
		return false
	}
	// Resolve the algorithm's options through a checked lookup. A key whose "alg" is not
	// an RSA signature algorithm — RSA-OAEP, or an EC alg on an RSA key — has no entry,
	// and indexing the map directly yields a nil interface whose HashFunc() panics.
	// Previously any non-PSS alg fell through to VerifyPKCS1v15, so a key labelled
	// RSA-OAEP (which NewRsaPublicKeyImpl admits) verified PKCS#1 v1.5 signatures under
	// an algorithm it does not name. The algorithm is the one captured at construction.
	opts, ok := algToOptsMap[k.alg]
	if !ok {
		return false
	}
	digester := opts.HashFunc().New()
	if _, err := digester.Write(data); err != nil {
		slog.Error("hash write error", "err", err)
		return false
	}
	digest := digester.Sum(nil)
	var err error
	if _, isPss := pssAlgs[k.alg]; isPss {
		err = rsa.VerifyPSS(&k.key, opts.HashFunc(), digest, signature, opts.(*rsa.PSSOptions))
	} else {
		err = rsa.VerifyPKCS1v15(&k.key, opts.HashFunc(), digest, signature)
	}
	return err == nil
}

// Encrypt encrypts the given plaintext returning the derived ciphertext.
func (k *RsaPublicKeyImpl) Encrypt(requested jose.KeyOps, hash crypto.Hash, data []byte) ([]byte, error) {
	/* Verify the operation being requested is supported by the jwk. */
	ops := intersection(validEncryptionOps, k.ops)
	if !isSubset(ops, []jose.KeyOps{requested}) {
		return nil, ErrInvalidOperations
	}
	// SHA1 is still safe when used in the construction of OAEP.
	return rsa.EncryptOAEP(hash.New(), rand.Reader, &k.key, data, nil)
}

// Certificates for verification key
func (k *RsaPublicKeyImpl) Certificates() []*x509.Certificate {
	return k.jwk.X5C()
}

// NewRsaPublicKeyImpl create a new RsaPublicKeyImpl instance.
func NewRsaPublicKeyImpl(jwk jose.Jwk) (*RsaPublicKeyImpl, error) {
	publicKey, err := LoadPublicKey(jwk, nil)
	if err != nil {
		return nil, err
	}
	// LoadPublicKey returns a *rsa.PublicKey; asserting the value type here always
	// failed, so this constructor rejected every RSA key with ErrInvalidKeyType.
	rsaKey, ok := publicKey.(*rsa.PublicKey)
	if !ok {
		return nil, ErrInvalidKeyType
	}
	return &RsaPublicKeyImpl{
		key: *rsaKey,
		jwk: jwk,
		ops: cloneOps(jwk.Ops()),
		alg: jwk.Alg(),
	}, nil
}
