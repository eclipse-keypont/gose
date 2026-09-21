// SPDX-FileCopyrightText: 2026 Thales Group and the gose Contributors
// SPDX-License-Identifier: MIT

package gose

import "github.com/eclipse-keypont/gose/jose"

var _ JweDecryptor = (*JweDirectDecryptorAeadImpl)(nil)

// JweDirectDecryptorAeadImpl is a concrete implementation of the JweDirectDecryptor interface.
type JweDirectDecryptorAeadImpl struct {
	keystore map[string]AeadEncryptionKey
}

// Decrypt and verify the given JWE returning both the plaintext and AAD.
func (decryptor *JweDirectDecryptorAeadImpl) Decrypt(jwe string) (plaintext, aad []byte, err error) {

	// This decryptor intentionally implements the legacy (non-RFC7516-compliant) JWE format.
	var jweStruct jose.Jwe
	if err = jweStruct.Unmarshal(jwe); err != nil {
		return
	}

	// We do not support zip conpression
	if jweStruct.Header.Zip != "" {
		err = ErrZipCompressionNotSupported
		return
	}

	// If there's no key ID specified fail.
	if len(jweStruct.Header.Kid) == 0 {
		err = ErrInvalidKid
		return
	}

	var key AeadEncryptionKey
	var exists bool
	if key, exists = decryptor.keystore[jweStruct.Header.Kid]; !exists {
		err = ErrUnknownKey
		return
	}

	enc, ok := gcmAlgToEncMap[key.Algorithm()]
	if !ok {
		err = ErrInvalidEncryption
		return
	}

	// Check alg is as expected, it's a direct encryption.
	if jweStruct.Header.Alg != jose.AlgDir || jweStruct.Header.Enc != enc {
		err = ErrInvalidAlgorithm
		return
	}

	if plaintext, err = key.Open(jose.KeyOpsDecrypt, jweStruct.Iv, jweStruct.Ciphertext, jweStruct.MarshalledHeader, jweStruct.Tag); err != nil {
		return
	}

	if jweStruct.Header.OtherAad != nil {
		aad = jweStruct.Header.OtherAad.Bytes()
	}

	return
}

// NewJweDirectDecryptorAeadImpl create a new instance of a JweDirectDecryptorAeadImpl.
func NewJweDirectDecryptorAeadImpl(keys []AeadEncryptionKey) *JweDirectDecryptorAeadImpl {
	// Create map out of our list of keys. The map is keyed in Kid.
	decryptor := &JweDirectDecryptorAeadImpl{
		keystore: map[string]AeadEncryptionKey{},
	}
	for _, key := range keys {
		decryptor.keystore[key.Kid()] = key
	}
	return decryptor
}
