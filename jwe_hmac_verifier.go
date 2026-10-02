// SPDX-FileCopyrightText: 2026 Thales Group and the gose Contributors
// SPDX-License-Identifier: MIT

package gose

import (
	"crypto/hmac"
	"fmt"

	"github.com/eclipse-keypont/gose/jose"
)

// JweHmacVerifierImpl implements the JWE Verification API
type JweHmacVerifierImpl struct {
	hmacKey HmacKey
}

func computeAL(aad []byte) []byte {
	// AL = AAD length
	//  is the octet string representing the number of bits in AAD expressed as a big-endian 64-bit unsigned integer
	return uintToBytesBigEndian(uint64(len(aad)))
}

// VerifyCompact verifies the authentication tag of a compact JWE (RFC 7516) matches its computed HMAC.
func (verifier *JweHmacVerifierImpl) VerifyCompact(jwe jose.JweRfc7516Compact) (result bool, err error) {
	// AAD
	//  = ASCII(BASE64URL(UTF8(JWE Protected Header)))
	var aad []byte
	if aad, err = jwe.ProtectedHeader.MarshalProtectedHeader(); err != nil {
		return false, fmt.Errorf("error marshalling the JWE Header: %w", err)
	}
	// Input HMAC computation
	// Concatenate the AAD, the Initialization Vector, the ciphertext and the AL value.
	inputHmac := concatByteArrays([][]byte{aad, jwe.InitializationVector, jwe.Ciphertext, computeAL(aad)})
	// compute the hash of it
	outputHmac := verifier.hmacKey.Hash(inputHmac)
	// Constant-time comparison prevents timing-based tag forgery for AES-CBC-HMAC.
	return hmac.Equal(outputHmac, jwe.AuthenticationTag), nil
}

// ComputeHash computes the HMAC authentication tag for the given AAD, initialization vector, and ciphertext.
func (verifier *JweHmacVerifierImpl) ComputeHash(aad []byte, iv []byte, ciphertext []byte) []byte {
	// Encrypt Plaintext to Create Ciphertext
	// Input HMAC computation
	// Concatenate the AAD, the Initialization Vector, the ciphertext and the AL value.
	inputHmac := concatByteArrays([][]byte{aad, iv, ciphertext, computeAL(aad)})
	// compute the hash of it
	return verifier.hmacKey.Hash(inputHmac)
}

// NewJweHmacVerifier creates a JWT Verifier for a given truststore
func NewJweHmacVerifier(hmacKey HmacKey) *JweHmacVerifierImpl {
	return &JweHmacVerifierImpl{hmacKey: hmacKey}
}
