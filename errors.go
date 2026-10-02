// SPDX-FileCopyrightText: 2026 Thales Group and the gose Contributors
// SPDX-License-Identifier: MIT

package gose

import "errors"

/* Errors. */
var (
	ErrInvalidKey               = errors.New("invalid jwk")
	ErrInvalidKeyType           = errors.New("invalid jwk type")
	ErrUnsupportedKeyType       = errors.New("unsupported jwk type")
	ErrInvalidSigningKeyURL     = errors.New("invalid signing jwk url")
	ErrInvalidOperations        = errors.New("the jwk is invalid in this context")
	ErrInvalidCertificateHeader = errors.New("invalid certificate header")
	ErrUnknownKey               = errors.New("unknown jwk")
	ErrInvalidSignature         = errors.New("invalid signature")
	ErrInconsistentKeyValues    = errors.New("inconsistent jwk values")
	ErrInvalidKeyLength         = errors.New("invalid jwk length")
	ErrHashUnavailable          = errors.New("hash unavailable")

	// RSA errors
	ErrInvalidExponentEncoding error = &InvalidFormat{"invalid exponent encoding"}
	ErrInvalidExponent               = errors.New("invalid exponent value")
	ErrInvalidModulusEncoding  error = &InvalidFormat{"invalid modulus encoding"}

	//EC errors
	ErrInvalidXEncoding error = &InvalidFormat{("Invalid X encoding")}
	ErrInvalidYEncoding error = &InvalidFormat{("Invalid Y encoding")}

	//GCM errors
	ErrInvalidNonce             = errors.New("invalid nonce")
	ErrInvalidAuthenticationTag = errors.New("invalid authentication tag")

	// JOSE errors
	ErrInvalidJwsCompactEncoding         error = &InvalidFormat{"invalid jws compact encoding"}
	ErrInvalidJwsBase64HeaderEncoding    error = &InvalidFormat{"invalid base64 jws header encoding"}
	ErrInvalidJwsHeaderEncoding          error = &InvalidFormat{"invalid jws header"}
	ErrInvalidJwsBase64BodyEncoding      error = &InvalidFormat{"invalid base64 jws body encoding"}
	ErrInvalidJwsBase64SignatureEncoding error = &InvalidFormat{"invalid base64 jws signature encoding"}
	ErrInvalidJwkEncoding                error = &InvalidFormat{"invalid jwk encoding"}
	ErrInvalidJwtEncoding                error = &InvalidFormat{"invalid jwt encoding"}
	ErrInvalidJwtTimeframe               error = &InvalidFormat{"invalid jwt time frame"}
	ErrInvalidKid                        error = &InvalidFormat{"invalid key ID"}
	ErrNoExpectedAudience                error = &InvalidFormat{"no expected audience"}
	ErrInvalidDelegateEncoding           error = &InvalidFormat{"invalid delegate encoding"}
	ErrInvalidManifestEncoding           error = &InvalidFormat{"invalid manifest encoding"}
	ErrInvalidKeySize                    error = &InvalidFormat{"invalid jwk size"}
	ErrInvalidAlgorithm                  error = &InvalidFormat{"invalid algorithm"}
	ErrInvalidEncryption                 error = &InvalidFormat{"invalid encryption"}
	ErrZipCompressionNotSupported        error = &InvalidFormat{"zip compression not supported"}
)
