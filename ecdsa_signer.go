// SPDX-FileCopyrightText: 2026 Thales Group and the gose Contributors
// SPDX-License-Identifier: MIT

package gose

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"log/slog"

	"math/big"

	"github.com/eclipse-keypont/gose/jose"
)

// ECDSAOptions Implements crypto.SignerOpts
type ECDSAOptions struct {
	Hash         crypto.Hash
	keySizeBytes int
	curveBits    int
	curve        elliptic.Curve
}

// HashFunc returns the crypto.Hash
func (opts *ECDSAOptions) HashFunc() crypto.Hash {
	return opts.Hash
}

//-------------------

// ECDSASigningKey implements ECDSA crypto.SigningKey
type ECDSASigningKey struct {
	jwk   jose.Jwk
	key   crypto.Signer
	certs []*x509.Certificate
}

// Algorithm returns the jose.Alg for this key
func (signer ECDSASigningKey) Algorithm() jose.Alg {
	return signer.jwk.Alg()
}

// Key returns the underlying key used to sign
func (signer *ECDSASigningKey) Key() crypto.Signer {
	return signer.key
}

// Sign digest and sign the given data.
// The output signature is encoded as r || s which is different to the standard go crypto interface specification.
// The serialization format is chosen instead to match that defined in the JSON Web Signature spec
// https://tools.ietf.org/html/rfc7515#appendix-A.3.1.
func (signer *ECDSASigningKey) Sign(requested jose.KeyOps, data []byte) (signature []byte, err error) {
	ops := intersection(validSignerOps, signer.jwk.Ops())
	if !isSubset(ops, []jose.KeyOps{requested}) {
		err = ErrInvalidOperations
		return
	}

	opts := algToOptsMap[signer.jwk.Alg()]
	if !opts.HashFunc().Available() {
		err = ErrHashUnavailable
		return
	}

	hasher := opts.HashFunc().New()
	if _, werr := hasher.Write(data); werr != nil {
		slog.Error("hash write error", "err", werr)
		return nil, werr
	}

	// Sign the string and return r, s
	key := signer.key.(*ecdsa.PrivateKey)

	var r, s *big.Int
	if r, s, err = ecdsa.Sign(rand.Reader, key, hasher.Sum(nil)); err == nil {
		curveBits := key.Curve.Params().BitSize
		options := opts.(*ECDSAOptions)
		if options.curveBits != curveBits {
			err = ErrInvalidKey
			return
		}

		keyBytes := (curveBits + 7) / 8

		// We serialize the outpus (r and s) into big-endian byte arrays and pad
		// them with zeros on the left to make sure the sizes work out. Both arrays
		// must be keyBytes long, and the output must be 2*keyBytes long.
		rBytes := r.Bytes()
		rBytesPadded := make([]byte, keyBytes, keyBytes*2)
		copy(rBytesPadded[keyBytes-len(rBytes):], rBytes)

		sBytes := s.Bytes()
		sBytesPadded := make([]byte, keyBytes)
		copy(sBytesPadded[keyBytes-len(sBytes):], sBytes)

		signature = append(rBytesPadded, sBytesPadded...)
		return
	}
	return
}

// Verifier get the matching verification key.
func (signer *ECDSASigningKey) Verifier() (VerificationKey, error) {
	publicJwk, err := PublicFromPrivate(signer.jwk)
	if err != nil {
		return nil, err
	}
	return NewVerificationKey(publicJwk)
}

// Kid returns the kid string value
func (signer *ECDSASigningKey) Kid() string {
	/* JIT jwk load. */
	return signer.jwk.Kid()
}

// Marshal marshals the key into a compact JWK representation or error
func (signer *ECDSASigningKey) Marshal() (string, error) {
	return JwkToString(signer.jwk)
}

const ecdsaPrivateKeyPerType = "ECDSA PRIVATE KEY"

// MarshalPem marshals the key into a PEM string or error
func (signer *ECDSASigningKey) MarshalPem() (p string, err error) {
	pemType := ecdsaPrivateKeyPerType
	var derEncoded []byte
	if derEncoded, err = x509.MarshalECPrivateKey(signer.key.(*ecdsa.PrivateKey)); err != nil {
		return
	}

	block := pem.Block{
		Type:  pemType,
		Bytes: derEncoded,
	}
	output := bytes.Buffer{}
	if err = pem.Encode(&output, &block); err != nil {
		return
	}
	return output.String(), nil

}

// Certificates returns certificate chain of this key
func (signer *ECDSASigningKey) Certificates() []*x509.Certificate {
	return signer.certs
}

// Jwk returns key as a jose.JWK type, or errors
func (signer *ECDSASigningKey) Jwk() (jose.Jwk, error) {
	/* Return a copy of our JWK. */
	return JwkFromPrivateKey(signer.key, signer.jwk.Ops(), signer.certs)
}
