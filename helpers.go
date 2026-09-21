// SPDX-FileCopyrightText: 2026 Thales Group and the gose Contributors
// SPDX-License-Identifier: MIT

package gose

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"math/big"
	"os"
	"strings"

	"crypto/ecdsa"
	"encoding/json"
	"log/slog"

	"github.com/eclipse-keypont/gose/jose"
)

const (
	//Version1 of the JOSE
	version1 = "v1"
)

func fromBase64(b64 string) (*big.Int, error) {
	b, err := base64.RawURLEncoding.DecodeString(b64)
	if err != nil {
		return nil, err
	}
	var result big.Int
	result.SetBytes(b)
	return &result, nil
}

func isSubset(set []jose.KeyOps, subset []jose.KeyOps) bool {
	if len(subset) == 0 {
		return false
	}
	result := true
	for _, req := range subset {
		opExists := false
		for _, op := range set {
			opExists = opExists || (req == op)
		}
		result = result && opExists
	}
	return result
}

func intersection(first []jose.KeyOps, second []jose.KeyOps) []jose.KeyOps {
	var result []jose.KeyOps
	for _, a := range first {
		for _, b := range second {
			if a == b {
				result = append(result, a)
			}
		}
	}
	return result
}

// ecdsaCurveForAlg resolves the elliptic curve for an EC JWK's "alg".
//
// A JWK's Go type is chosen from "kty" alone and is never cross-validated against
// "alg", so an EC key can arrive carrying an RSA alg — RFC 7517 §4.4 permits it and
// the document is well formed. algToOptsMap then yields a crypto.Hash, a
// *rsa.PSSOptions, or nothing at all, and an unchecked assertion to *ECDSAOptions
// panics. Resolving through this helper turns that into an error.
func ecdsaCurveForAlg(alg jose.Alg) (elliptic.Curve, error) {
	opts, ok := algToOptsMap[alg].(*ECDSAOptions)
	if !ok {
		return nil, ErrInvalidKeyType
	}
	return opts.curve, nil
}

// LoadPrivateKey loads the jwk into a crypto.Signer for performing signing operations
func LoadPrivateKey(jwk jose.Jwk, required []jose.KeyOps) (crypto.Signer, error) {
	privateKeyAlgs := map[jose.Alg]bool{
		jose.AlgRS256:       true,
		jose.AlgRS384:       true,
		jose.AlgRS512:       true,
		jose.AlgPS256:       true,
		jose.AlgPS384:       true,
		jose.AlgPS512:       true,
		jose.AlgES256:       true,
		jose.AlgES384:       true,
		jose.AlgES512:       true,
		jose.AlgRSAOAEP:     true,
		jose.AlgRSAOAEPSHA2: true,
	}

	if _, ok := privateKeyAlgs[jwk.Alg()]; !ok {
		return nil, ErrInvalidKeyType
	}
	if len(required) > 0 && !isSubset(jwk.Ops(), required) {
		return nil, ErrInvalidOperations
	}
	switch v := jwk.(type) {
	case *jose.PrivateRsaKey:
		/* Import RSA private key. */
		if v.D.Empty() || v.E.Empty() || v.N.Empty() {
			/* This is a public RSA jwk. */
			return nil, ErrInvalidKeyType
		}
		var key rsa.PrivateKey

		/* Ensure positive 32-bit integer. */
		if v.E.Int().BitLen() > 32 || v.E.Int().Sign() < 1 {
			return nil, ErrInvalidExponent
		}

		key.Primes = []*big.Int{v.P.Int(), v.Q.Int()}
		key.D = v.D.Int()
		key.E = int(v.E.Int().Int64())
		key.N = v.N.Int()
		key.Precompute()
		// Check the consistency of the precomputable values contained in the JWK.
		if key.Precomputed.Dp.Cmp(v.Dp.Int()) != 0 || key.Precomputed.Dq.Cmp(v.Dq.Int()) != 0 || key.Precomputed.Qinv.Cmp(v.Qi.Int()) != 0 {
			return nil, ErrInconsistentKeyValues
		}
		return &key, nil
	case *jose.PrivateEcKey:
		if v.D.Empty() {
			/* This is a public jwk. */
			return nil, ErrInvalidKeyType
		}
		var key ecdsa.PrivateKey

		key.X = v.X.Int()
		key.Y = v.Y.Int()
		key.D = v.D.Int()
		curve, err := ecdsaCurveForAlg(v.Alg())
		if err != nil {
			return nil, err
		}
		key.Curve = curve
		return &key, nil
	default:
		return nil, ErrUnsupportedKeyType
	}
}

// LoadPublicKey loads jwk as a public key for cryptographic verification operations.
func LoadPublicKey(jwk jose.Jwk, required []jose.KeyOps) (crypto.PublicKey, error) {
	publicKeyAlgs := map[jose.Alg]bool{
		jose.AlgRS256:       true,
		jose.AlgRS384:       true,
		jose.AlgRS512:       true,
		jose.AlgPS256:       true,
		jose.AlgPS384:       true,
		jose.AlgPS512:       true,
		jose.AlgES256:       true,
		jose.AlgES384:       true,
		jose.AlgES512:       true,
		jose.AlgRSAOAEP:     true,
		jose.AlgRSAOAEPSHA2: true,
	}
	if _, ok := publicKeyAlgs[jwk.Alg()]; !ok {
		return nil, ErrInvalidKeyType
	}
	if len(required) > 0 && !isSubset(jwk.Ops(), required) {
		return nil, ErrInvalidOperations
	}
	switch v := jwk.(type) {
	case *jose.PublicRsaKey:
		/* Import RSA private jwk. */
		if v.N.Empty() || v.E.Empty() {
			/* There's no public parameters. */
			return nil, ErrInvalidKeyType
		}
		var key rsa.PublicKey
		/* Ensure positive 32-bit integer. */
		if v.E.Int().BitLen() > 32 || v.E.Int().Sign() < 1 {
			return nil, ErrInvalidExponent
		}
		key.E = int(v.E.Int().Int64())
		key.N = v.N.Int()
		return &key, nil
	case *jose.PublicEcKey:
		var key ecdsa.PublicKey
		if v.X.Empty() || v.Y.Empty() {
			/* There's no public parameters. */
			return nil, ErrInvalidKeyType
		}
		key.X = v.X.Int()
		key.Y = v.Y.Int()
		curve, err := ecdsaCurveForAlg(v.Alg())
		if err != nil {
			return nil, err
		}
		key.Curve = curve
		return &key, nil
	default:
		return nil, ErrUnsupportedKeyType
	}
}

// LoadJws loads signature, or errors
func LoadJws(jws string) (protectedHeader *jose.JwsHeader, header []byte, data []byte, payload []byte, signature []byte, err error) {
	var tmp jose.JwsHeader
	parts := strings.SplitN(jws, ".", 3)
	if len(parts) != 3 {
		return nil, nil, nil, nil, nil, ErrInvalidJwsCompactEncoding
	}
	header, err = base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, nil, nil, nil, nil, ErrInvalidJwsBase64HeaderEncoding
	}
	if err := json.Unmarshal(header, &tmp); err != nil {
		return nil, nil, nil, nil, nil, ErrInvalidJwsHeaderEncoding
	}
	protectedHeader = &tmp
	data, err = base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, nil, nil, nil, nil, ErrInvalidJwsBase64BodyEncoding
	}
	signature, err = base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, nil, nil, nil, nil, ErrInvalidJwsBase64SignatureEncoding
	}
	payload = []byte(fmt.Sprintf("%s.%s", parts[0], parts[1]))
	return
}

// CalculateKeyID deterministically calculates the ID for the given jwk
func CalculateKeyID(jwk jose.Jwk) (string, error) {
	/* Deterministic calculation of a jwk's identity. */
	switch typed := jwk.(type) {
	case *jose.PublicRsaKey:
		encoded := strings.Join([]string{
			version1,
			"jwk",
			string(jwk.Kty()),
			base64.RawURLEncoding.EncodeToString(typed.N.Int().Bytes()),
			base64.RawURLEncoding.EncodeToString(typed.E.Int().Bytes()),
		}, ".")
		digester := sha256.New()
		if _, err := digester.Write([]byte(encoded)); err != nil {
			slog.Error("hash write error", "err", err)
			return "", err
		}
		digest := digester.Sum(nil)
		return fmt.Sprintf("%x", digest), nil
	case *jose.PublicEcKey:
		encoded := strings.Join([]string{
			version1,
			"jwk",
			string(jwk.Kty()),
			base64.RawURLEncoding.EncodeToString(typed.X.Int().Bytes()),
			base64.RawURLEncoding.EncodeToString(typed.Y.Int().Bytes()),
		}, ".")
		digester := sha256.New()
		if _, err := digester.Write([]byte(encoded)); err != nil {
			slog.Error("hash write error", "err", err)
			return "", err
		}
		digest := digester.Sum(nil)
		return fmt.Sprintf("%x", digest), nil
	case *jose.OctSecretKey:
		// Should we include alg in symmetric jwk
		// identification? The spec is RFC7517 s4.5 and does
		// not give a clear steer. I've adopted the answer
		// 'no' for now but we might want to revisit this.
		digester := sha256.New()
		encoded := strings.Join([]string{
			version1,
			"jwk",
			string(jwk.Kty()),
			base64.RawURLEncoding.EncodeToString(typed.K.Bytes()),
		}, ".")
		if _, err := digester.Write([]byte(encoded)); err != nil {
			slog.Error("hash write error", "err", err)
			return "", err
		}
		digest := digester.Sum(nil)
		return fmt.Sprintf("%x", digest), nil
	default:
		return "", ErrUnsupportedKeyType
	}
}

// LoadJwk load io.ReadSeeker as a JWK or error
func LoadJwk(reader io.ReadSeeker, required []jose.KeyOps) (jwk jose.Jwk, err error) {
	if jwk, err = jose.UnmarshalJwk(reader); err != nil {
		return
	}
	if len(required) > 0 && !isSubset(jwk.Ops(), required) {
		return
	}
	return
}

// LoadJwkFromFile loads file as JWK or error
func LoadJwkFromFile(file string, required []jose.KeyOps) (jose.Jwk, error) {
	/* Load jwk from file. */
	fd, err := os.Open(file) // #nosec G304 -- file path is a caller-supplied argument to this public API
	if err != nil {
		return nil, ErrInvalidSigningKeyURL
	}
	defer func() { _ = fd.Close() }()
	return LoadJwk(fd, required)
}

var inverseOps = map[jose.KeyOps]jose.KeyOps{
	jose.KeyOpsEncrypt: jose.KeyOpsDecrypt,
	jose.KeyOpsDecrypt: jose.KeyOpsEncrypt,
	jose.KeyOpsSign:    jose.KeyOpsVerify,
	jose.KeyOpsVerify:  jose.KeyOpsSign,
}

// rsaBitsToAlg maps RSA key size to the recommended signing algorithm (PS family)
// based on NIST 2016 recommendations.
func rsaBitsToAlg(bitLen int) jose.Alg {
	if bitLen >= 15360 {
		return jose.AlgPS512
	} else if bitLen >= 7680 {
		return jose.AlgPS384
	}
	return jose.AlgPS256
}

// rsaAlgFromOps selects the RSA algorithm based on intended key operations:
// encryption/decryption uses AlgRSAOAEP; all other operations fall back to the
// key-size-based signing algorithm from rsaBitsToAlg.
func rsaAlgFromOps(bitLen int, ops []jose.KeyOps) jose.Alg {
	for _, op := range ops {
		if op == jose.KeyOpsEncrypt || op == jose.KeyOpsDecrypt {
			return jose.AlgRSAOAEP
		}
	}
	return rsaBitsToAlg(bitLen)
}

func ecBitsToAlg(bitLen int) jose.Alg {
	switch bitLen {
	case 256:
		return jose.AlgES256
	case 384:
		return jose.AlgES384
	case 521:
		return jose.AlgES512
	default:
		return "Unsupported"
	}
}

// PublicFromPrivate extracts public jwk from private jwk in JWK format
func PublicFromPrivate(in jose.Jwk) (jose.Jwk, error) {
	var out jose.Jwk
	switch k := in.(type) {
	case *jose.PrivateRsaKey:
		if k.D.Empty() || k.Q.Empty() || k.Dq.Empty() || k.P.Empty() ||
			k.Dp.Empty() || k.Qi.Empty() || k.N.Empty() || k.E.Empty() {
			/* This is either badly formed or a public jwk. */
			return nil, ErrInvalidKeyType
		}
		var result jose.PublicRsaKey
		result.PublicRsaKeyFields = k.PublicRsaKeyFields
		out = &result
	case *jose.PrivateEcKey:
		var result jose.PublicEcKey
		result.PublicEcKeyFields = k.PublicEcKeyFields
		out = &result
	default:
		return nil, ErrUnsupportedKeyType
	}
	out.SetKid(in.Kid())
	out.SetAlg(in.Alg())
	var ops []jose.KeyOps
	for _, op := range in.Ops() {
		ops = append(ops, inverseOps[op])
	}
	out.SetOps(ops)
	out.SetX5C(in.X5C())
	return out, nil
}

// JwkToString return JWK as string
func JwkToString(jwk jose.Jwk) (string, error) {
	b, err := json.Marshal(jwk)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func uintToBytesBigEndian(val uint64) []byte {
	var buf bytes.Buffer
	if err := binary.Write(&buf, binary.BigEndian, &val); err != nil {
		slog.Error("binary write error", "err", err)
	}
	return buf.Bytes()
}

func concatByteArrays(slices [][]byte) []byte {
	var tmp []byte
	for _, s := range slices {
		tmp = append(tmp, s...)
	}
	return tmp
}

// JwkFromPrivateKey builds JWK, from a crypto.Signer, with certificates, and scoped to certain operations,  or errors
func JwkFromPrivateKey(privateKey crypto.Signer, operations []jose.KeyOps, certs []*x509.Certificate) (jose.Jwk, error) {
	var jwk jose.Jwk
	switch v := privateKey.(type) {
	case *rsa.PrivateKey:
		if v.E > math.MaxInt32 {
			return nil, ErrInvalidExponent
		}
		alg := rsaAlgFromOps(v.N.BitLen(), operations)
		/* Key generation. */
		v.Precompute()
		var rsa jose.PrivateRsaKey
		rsa.SetAlg(alg)
		rsa.Q.Set(v.Primes[1])
		rsa.Qi.Set(v.Precomputed.Qinv)
		rsa.Dq.Set(v.Precomputed.Dq)
		rsa.P.Set(v.Primes[0])
		rsa.Dp.Set(v.Precomputed.Dp)
		rsa.N.Set(v.N)
		rsa.E.Set(big.NewInt(int64(v.E)))
		rsa.D.Set(v.D)
		jwk = &rsa
	case *ecdsa.PrivateKey:
		var ec jose.PrivateEcKey
		alg := ecBitsToAlg(v.Curve.Params().BitSize)
		ec.SetAlg(alg)
		ec.X.Set(v.X)
		ec.Y.Set(v.Y)
		ec.D.Set(v.D)
		ec.Crv = jose.Crv(v.Curve.Params().Name)
		jwk = &ec
	default:
		return nil, ErrUnsupportedKeyType
	}
	jwk.SetOps(operations)
	if len(certs) > 0 {
		jwk.SetX5C(certs)
	}
	publicKey, err := PublicFromPrivate(jwk)
	if err != nil {
		// We should have erred before we ever get here.
		slog.Error("failed to derive public jwk from private", "err", err)
		return nil, err
	}
	kid, err := CalculateKeyID(publicKey)
	if err != nil {
		// We should have erred before we ever get here.
		slog.Error("failed to calculate key ID", "err", err)
		return nil, err
	}
	jwk.SetKid(kid)

	return jwk, nil
}

// JwkFromPublicKey builds public JWK, from a crypto.Signer, with certificates, and scoped to certain operations,  or errors
func JwkFromPublicKey(publicKey crypto.PublicKey, operations []jose.KeyOps, certs []*x509.Certificate) (jose.Jwk, error) {
	var jwk jose.Jwk
	switch v := publicKey.(type) {
	case *rsa.PublicKey:
		if v.E > math.MaxInt32 {
			return nil, ErrInvalidExponent
		}
		alg := rsaAlgFromOps(v.N.BitLen(), operations)
		/* Key generation. */
		var rsa jose.PublicRsaKey
		rsa.SetAlg(alg)
		rsa.N.Set(v.N)
		rsa.E.Set(big.NewInt(int64(v.E)))
		jwk = &rsa
	case *ecdsa.PublicKey:
		var ec jose.PublicEcKey
		alg := ecBitsToAlg(v.Curve.Params().BitSize)
		ec.SetAlg(alg)
		ec.X.Set(v.X)
		ec.Y.Set(v.Y)
		ec.Crv = jose.Crv(v.Curve.Params().Name)
		jwk = &ec
	default:
		return nil, ErrUnsupportedKeyType
	}
	jwk.SetOps(operations)
	kid, err := CalculateKeyID(jwk)
	if err != nil {
		slog.Error("failed to calculate key ID", "err", err)
		return nil, err
	}
	jwk.SetKid(kid)
	if len(certs) > 0 {
		jwk.SetX5C(certs)
	}
	return jwk, nil
}

// Characteristics of symmetric algorithms
type symmetricAlgInfo struct {
	minLen          int
	maxLen          int
	confidentiality bool
	integrity       bool
}

// Table of known symmetric algorithms
var symmetricAlgs = map[jose.Alg]symmetricAlgInfo{
	jose.AlgA128GCM: {16, 16, true, true},
	jose.AlgA192GCM: {24, 24, true, true},
	jose.AlgA256GCM: {32, 32, true, true},
}

// JwkFromSymmetric converts a byte string to a jose.Jwk, given a particular JWK algorithm.
func JwkFromSymmetric(key []byte, alg jose.Alg) (jwk *jose.OctSecretKey, err error) {
	// Validity checking & default ops
	ops := make([]jose.KeyOps, 0, 4)
	if sai, ok := symmetricAlgs[alg]; ok {
		if len(key) < sai.minLen || len(key) > sai.maxLen {
			err = ErrInvalidKeyLength
			return
		}
		if sai.confidentiality {
			ops = append(ops, jose.KeyOpsEncrypt, jose.KeyOpsDecrypt)
		}
		if sai.integrity {
			ops = append(ops, jose.KeyOpsSign, jose.KeyOpsVerify)
		}
	} else {
		err = ErrUnsupportedKeyType
		return
	}
	oct := jose.OctSecretKey{}
	oct.SetOps(ops)
	oct.SetAlg(alg)
	oct.K.SetBytes(key)
	var kid string
	if kid, err = CalculateKeyID(&oct); err != nil {
		return
	}
	oct.SetKid(kid)
	jwk = &oct
	return
}

// Extract the raw bytes of a symmetric jwk. Only 'oct' keys are supported.
func loadSymmetricBytes(jwk jose.Jwk, required []jose.KeyOps) (key []byte, err error) {
	// TODO I made this private to discourage promiscuous use of
	// raw key bytes, but if required it could easily be public.
	if _, ok := symmetricAlgs[jwk.Alg()]; !ok {
		err = ErrInvalidKeyType
		return
	}
	if len(required) > 0 && !isSubset(jwk.Ops(), required) {
		err = ErrInvalidOperations
		return
	}
	switch v := jwk.(type) {
	case *jose.OctSecretKey:
		key = v.K.Bytes()
		return
	default:
		err = ErrUnsupportedKeyType
		return
	}
}

// LoadSymmetricAEAD returns a cipher.AEAD for a jwk.
func LoadSymmetricAEAD(jwk jose.Jwk, required []jose.KeyOps) (a cipher.AEAD, err error) {
	var key []byte
	if key, err = loadSymmetricBytes(jwk, required); err != nil {
		return
	}
	v := jwk.(*jose.OctSecretKey) // can't fail, previous call would have errored
	switch v.Alg() {
	case jose.AlgA128GCM, jose.AlgA192GCM, jose.AlgA256GCM:
		var b cipher.Block
		if b, err = aes.NewCipher(key); err != nil {
			return
		}
		if a, err = cipher.NewGCM(b); err != nil {
			return
		}
		return
	default:
		err = ErrUnsupportedKeyType
		return
	}
}

// GetALFromAAD takes the AAD field of a JWE and compute the AL field
// AL is the octet string of the number of bits in AAD expressed as a big endian 64-bit unsigned integer.
// For example, if AAD is 51 bytes long, which is 408 bits long, the octet string AL, which is the number of bits in AAD expressed as a big endian 64 bit unsigned integer is [0, 0, 0, 0, 0, 0, 1, 152].
func GetALFromAAD(aad []byte) (al []byte) {
	// Convert the length to bits
	aadLengthBits := uint64(len(aad) * 8) // 51 bytes * 8 bits/byte = 408 bits
	// Create a byte slice to hold the big-endian 64-bit unsigned integer
	al = make([]byte, 8)
	// Convert the length in bits to a big-endian 64-bit unsigned integer
	binary.BigEndian.PutUint64(al, aadLengthBits)
	return
}
