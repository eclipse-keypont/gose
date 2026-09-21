// SPDX-FileCopyrightText: 2026 Thales Group and the gose Contributors
// SPDX-License-Identifier: MIT

// Package jose implements the data types for JWK, JWS, and JWE as defined by RFC 7515-7517.
package jose

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
)

// Alg is a type for representing values destined for `alg` fields in JWK and JWTs.
type Alg string

// Crv is a type for representing values destined for `crv` fields in JWKs.
type Crv string

// Kty is a type for representing values destined for `kty` fields in JWKs.
type Kty string

// KeyUse is a type for representing values destined for `use` fields in JWKs.
type KeyUse string

// KeyOps is a type for representing values destined for `key_ops` fields in JWKs.
type KeyOps string

// JwsType is a type for representing values destined for `typ` fields in JWS and JWTs.
type JwsType string

// Enc is a type representing values destined for the `enc` field in a JWE header.
type Enc string

// Zip is a type representing values destined for the `zip` field in a JWE header.
type Zip string

// Header holds the common JOSE header fields shared by JWS and JWE.
type Header struct {
	Alg Alg    `json:"alg"`
	Jku string `json:"jku,omitempty"`
	//jwkFields []jwkFields `json:"jwk,omitempty"`  TODO finish this
	Kid    string   `json:"kid,omitempty"`
	X5U    string   `json:"x5u,omitempty"`
	X5C    [][]byte `json:"x5c,omitempty"`
	X5T    *Blob    `json:"x5t,omitempty"`
	X5T256 *Blob    `json:"x5t#S256,omitempty"`
	Typ    JwsType  `json:"typ,omitempty"`
	Cty    JwsType  `json:"cty,omitempty"`
}

const (
	// Supported Algorithms

	//AlgRS256 RSA PKCS #1 and SHA-2 256
	AlgRS256 Alg = "RS256"
	//AlgRS384 RSA PKCS #1 and SHA-2 384
	AlgRS384 Alg = "RS384"
	//AlgRS512 RSA PKCS #1 and SHA-2 512
	AlgRS512 Alg = "RS512"
	//AlgPS256 RSA PSS signature with SHA-2 256
	AlgPS256 Alg = "PS256"
	//AlgPS384 RSA PSS signature with SHA-2 384
	AlgPS384 Alg = "PS384"
	//AlgPS512 RSA PSS signature with SHA-2 512
	AlgPS512 Alg = "PS512"
	//AlgES256 EC DSA signature with SHA-2 256
	AlgES256 Alg = "ES256"
	//AlgES384 EC DSA signature with SHA-2 384
	AlgES384 Alg = "ES384"
	//AlgES512 EC DSA signature with SHA-2 512
	AlgES512 Alg = "ES512"
	//AlgA128GCM AES GCM using 128-bit key
	AlgA128GCM Alg = "A128GCM"
	//AlgA192GCM AES GCM using 192-bit key
	AlgA192GCM Alg = "A192GCM"
	//AlgA256GCM AES GCM using 256-bit key
	AlgA256GCM Alg = "A256GCM"
	//AlgA256CBC AES CBC using 256-bit key
	AlgA256CBC Alg = "A256CBC"
	// AlgDir direct encryption for use with JWEs
	AlgDir Alg = "dir"
	// AlgRSAOAEP RSAES-OAEP with SHA-1 and MGF1 with SHA-1, as registered by RFC 7518 §4.3.
	// Alias of AlgRSAOAEPSHA1; prefer the explicitly named constant in new code.
	AlgRSAOAEP Alg = "RSA-OAEP"
	// AlgRSAOAEPSHA1 RSAES-OAEP with SHA-1, RFC 7518 §4.3.
	// Some KMS, notably SoftHSMv2, implement only the SHA-1 variant, so gose supports both
	// this and AlgRSAOAEPSHA2. The two are distinct on the wire: a JWE header advertising
	// "RSA-OAEP" is decryptable only with SHA-1, and "RSA-OAEP-256" only with SHA-256.
	AlgRSAOAEPSHA1 Alg = "RSA-OAEP"
	// AlgRSAOAEPSHA2 RSAES-OAEP with SHA-256 and MGF1 with SHA-256, RFC 7518 §4.3.
	// See AlgRSAOAEPSHA1 for why both variants exist.
	AlgRSAOAEPSHA2 Alg = "RSA-OAEP-256"

	//CrvP256 NIST P-256
	CrvP256 Crv = "P-256"
	//CrvP384 NIST P-384
	CrvP384 Crv = "P-384"
	//CrvP521 NIST P-521
	CrvP521 Crv = "P-521"

	// Key Types

	//KtyRSA RSA key type
	KtyRSA Kty = "RSA"
	//KtyEC Elliptical Curve key type
	KtyEC Kty = "EC"
	//KtyOct Octet key type
	KtyOct Kty = "oct"

	//KeyUseEnc encryption usage
	KeyUseEnc KeyUse = "enc"
	//KeyUseSig signing usage
	KeyUseSig KeyUse = "sig"

	//Key Operations - Standard

	//KeyOpsSign sign stuff
	KeyOpsSign KeyOps = "sign"
	//KeyOpsVerify verify signed stuff
	KeyOpsVerify KeyOps = "verify"
	//KeyOpsEncrypt encrypt stuff
	KeyOpsEncrypt KeyOps = "encrypt"
	//KeyOpsDecrypt decrypt stuff
	KeyOpsDecrypt KeyOps = "decrypt"
	//KeyOpsWrapKey wrap keys
	KeyOpsWrapKey KeyOps = "wrapKey"
	//KeyOpsUnwrapKey unwrap keys
	KeyOpsUnwrapKey KeyOps = "unwrapKey"
	//KeyOpsDeriveKey derive a key
	KeyOpsDeriveKey KeyOps = "deriveKey"
	//KeyOpsDeriveBits derive bits
	KeyOpsDeriveBits KeyOps = "deriveBits"

	//JwtType JWT type
	JwtType JwsType = "JWT"

	// EncA128GCM AES GCM 128 Enc type
	EncA128GCM Enc = "A128GCM"
	// EncA192GCM AES GCM 192 Enc type
	EncA192GCM Enc = "A192GCM"
	// EncA256GCM AES GCM 256 Enc type
	EncA256GCM Enc = "A256GCM"
	// EncA256CBC AES CBC 256 Enc type
	EncA256CBC Enc = "A256CBC"

	// DeflateZip deflate type
	DeflateZip Zip = "DEF"
)

var (
	//ErrJSONFormat when bad JSON string provided
	ErrJSONFormat = errors.New("invalid JSON format")
	//ErrBlobEmpty when bad Blob provided
	ErrBlobEmpty = errors.New("invalid Blob format, may not be empty")
	//ErrUnsupportedKeyType when a key type is unknown/unsupported
	ErrUnsupportedKeyType = errors.New("unsupported key type")
	//ErrUnexpectedKeyType when a key shows up in the wrong place.
	ErrUnexpectedKeyType = errors.New("unexpected key type")
	//ErrJwtFormat when a JWT isn't formatted correctly
	ErrJwtFormat = errors.New("invalid JWT format")
	//ErrDuplicateKeyOps too many of the same operation requested
	ErrDuplicateKeyOps = errors.New("duplicate key_ops entries")
	//ErrJwkInconsistentCertificateFields when a certificates fields are not what was expected
	ErrJwkInconsistentCertificateFields = errors.New("inconsistent certificate fields")
	//ErrJwkInvalidFingerprintfomat the fingerprint field (x5t) is encoded in an incorrect format
	ErrJwkInvalidFingerprintfomat = errors.New("invalid fingerprint format")

	//ErrJwkReservedClaimName invalid use of a reserved/defined claim name
	ErrJwkReservedClaimName = errors.New("incorrect use of reserved claim name")

	//ErrJweFormat when a JWE isn't formatted correctly
	ErrJweFormat = errors.New("invalid JWE format")

	//ErrTooManyKeyOps when a JWK declares more key_ops entries than can plausibly be
	//meaningful. RFC 7517 §4.3 defines a small fixed set; a document carrying thousands
	//is malformed, and bounding it keeps key_ops validation cheap.
	ErrTooManyKeyOps = errors.New("too many key_ops entries")

	//ErrCritHeaderNotSupported when a JWS/JWT carries a non-empty "crit" header. gose
	//implements no JWS header extensions, so RFC 7515 §4.1.11 requires rejecting any
	//token that marks extensions as critical.
	ErrCritHeaderNotSupported = errors.New("unsupported critical header parameter")
)

func unmarshalJSONBlob(src []byte, decoder *base64.Encoding) (dst []byte, err error) {
	srcLen := len(src)
	// We always want at least 1 character pre and proceeded by a quote.
	if srcLen < 3 || src[0] != '"' || src[srcLen-1] != '"' {
		err = ErrBlobEmpty
		return
	}
	// Allocate (possibly over allocate) our dst buffer.
	dstLen := decoder.DecodedLen(srcLen - 2)
	tmp := make([]byte, dstLen)
	var decoded int
	if decoded, err = decoder.Decode(tmp, src[1:srcLen-1]); err != nil {
		return
	}
	// Only return the exact length buffer
	dst = tmp[:decoded]
	return
}

func marshalJSONBlob(src []byte, encoder *base64.Encoding) (dst []byte, err error) {

	if len(src) == 0 {
		err = ErrBlobEmpty
		return
	}

	dstLen := encoder.EncodedLen(len(src)) + 2
	dst = make([]byte, dstLen)
	dst[0] = '"'
	dst[dstLen-1] = '"'
	encoder.Encode(dst[1:dstLen-1], src)
	return
}

// BigNum for managing big.Int
type BigNum struct {
	b big.Int
}

// SetBytes of BigNum
func (b *BigNum) SetBytes(val []byte) *BigNum {
	b.b.SetBytes(val)
	return b
}

// Set bigNum with bit.Int
func (b *BigNum) Set(val *big.Int) *BigNum {
	b.b.SetBytes(val.Bytes())
	return b
}

// Int as big.Int
func (b *BigNum) Int() *big.Int {
	return &b.b
}

// Empty out BigNum
func (b *BigNum) Empty() bool {
	return b.b.BitLen() == 0
}

// MarshalJSON as byte slice or error
func (b *BigNum) MarshalJSON() (dst []byte, err error) {
	dst, err = marshalJSONBlob(b.b.Bytes(), base64.RawURLEncoding)
	return
}

// UnmarshalJSON byte slice or error
func (b *BigNum) UnmarshalJSON(src []byte) (err error) {
	var dst []byte
	if dst, err = unmarshalJSONBlob(src, base64.RawURLEncoding); err != nil {
		return
	}
	b.SetBytes(dst)
	return
}

// Blob represents a url-safe base64 encoded byte block.
type Blob struct {
	B []byte
}

// Bytes of blob in byte slice
func (b *Blob) Bytes() []byte {
	return b.B
}

// UnmarshalJSON byte slice to Blob, or error
func (b *Blob) UnmarshalJSON(src []byte) error {
	var err error
	b.B, err = unmarshalJSONBlob(src, base64.RawURLEncoding)
	return err
}

// MarshalJSON blob to byte slice
func (b *Blob) MarshalJSON() (dst []byte, err error) {
	dst, err = marshalJSONBlob(b.B, base64.RawURLEncoding)
	return
}

// SetBytes of blob
func (b *Blob) SetBytes(val []byte) *Blob {
	b.B = val
	return b
}

func unmarshalURLBase64(data string, inst interface{}) error {
	var raw []byte
	var err error
	if raw, err = base64.RawURLEncoding.DecodeString(data); err != nil {
		return err
	}

	if err = json.Unmarshal(raw, inst); err != nil {
		return err
	}
	return nil
}
