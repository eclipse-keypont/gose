// SPDX-FileCopyrightText: 2026 Thales Group and the gose Contributors
// SPDX-License-Identifier: MIT

package gose

import (
	"fmt"

	"github.com/eclipse-keypont/gose/jose"
)

// cbcAlgToEncMap maps CBC/GCM key algorithms to their JWE enc header values.
// Initialized once at package startup — treat as read-only; mutating it is a data race.
var (
	cbcAlgToEncMap = map[jose.Alg]jose.Enc{
		jose.AlgA256CBC: jose.EncA256CBC,
		jose.AlgA256GCM: jose.EncA256GCM,
	}
)

// JweDirectEncryptorBlock is an implementation of the JweDirectEncryptionEncryptor interface for BlockMode which is
// more efficient than Block for bulk operations.
type JweDirectEncryptorBlock struct {
	aesKey      BlockEncryptionKey
	iv          []byte
	jweVerifier JweHmacVerifierImpl
}

// makeJweProtectedHeader builds the JWE structure
func (encryptor *JweDirectEncryptorBlock) makeJweProtectedHeader() *jose.JweProtectedHeader {
	return &jose.JweProtectedHeader{
		JwsHeader: jose.JwsHeader{
			Alg: encryptor.aesKey.Algorithm(),
			Kid: encryptor.aesKey.Kid(),
			Typ: "JWT",
			Cty: "JWT",
		},
		Enc: cbcAlgToEncMap[encryptor.aesKey.Algorithm()],
	}
}

// Encrypt encrypts the given plaintext and returns a compact JWE.
//
//	WARNING aad is useless here : according to RFC7516, the AAD is computed from the JWE's private header
//	It is just here to statisfy the interface implementation
func (encryptor *JweDirectEncryptorBlock) Encrypt(plaintext, _ []byte) (string, error) {
	// The following steps respect the RFC7516 Appendix B for AES CBC and HMAC encryption instructions :
	// https://datatracker.ietf.org/doc/html/rfc7516#appendix-B
	var err error
	// iv
	iv := encryptor.iv
	// JWE header
	jweProtectedHeader := encryptor.makeJweProtectedHeader()
	// Store the plaintext length in OtherAad BEFORE marshalling the header so
	// that the AAD bytes fed to HMAC during encryption are identical to those
	// the verifier will reconstruct during decryption (which sees the full
	// serialised header including this field).
	jweProtectedHeader.OtherAad = &jose.Blob{
		B: uintToBytesBigEndian(uint64(len(plaintext))),
	}
	// AAD = ASCII(BASE64URL(UTF8(JWE Protected Header)))
	var aad []byte
	if aad, err = jweProtectedHeader.MarshalProtectedHeader(); err != nil {
		return "", fmt.Errorf("error marshalling the JWE Header: %w", err)
	}
	// Encrypt Plaintext to Create Ciphertext
	ciphertext := encryptor.aesKey.Seal(plaintext)
	// HMAC computation
	outputHmac := encryptor.jweVerifier.ComputeHash(aad, iv, ciphertext)
	// Create Authentication Tag
	//tag := outputHmac[:(len(outputHmac) / 2)]
	tag := outputHmac
	jwe := &jose.JweRfc7516Compact{
		ProtectedHeader:      *jweProtectedHeader,
		EncryptedKey:         nil,
		InitializationVector: iv,
		Ciphertext:           ciphertext,
		AuthenticationTag:    tag,
	}
	return jwe.Marshal()
}

// NewJweDirectEncryptorBlock construct an instance of a JweDirectEncryptorBlock.
func NewJweDirectEncryptorBlock(aesKey BlockEncryptionKey, hmacKey HmacKey, iv []byte) *JweDirectEncryptorBlock {
	return &JweDirectEncryptorBlock{
		aesKey:      aesKey,
		iv:          iv,
		jweVerifier: JweHmacVerifierImpl{hmacKey: hmacKey},
	}
}
