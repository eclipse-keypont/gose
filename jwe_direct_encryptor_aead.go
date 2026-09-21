// SPDX-FileCopyrightText: 2026 Thales Group and the gose Contributors
// SPDX-License-Identifier: MIT

package gose

import (
	"github.com/eclipse-keypont/gose/jose"
)

// gcmAlgToEncMap maps GCM key algorithms to their JWE enc header values.
// Initialized once at package startup — treat as read-only; mutating it is a data race.
var (
	gcmAlgToEncMap = map[jose.Alg]jose.Enc{
		jose.AlgA128GCM: jose.EncA128GCM,
		jose.AlgA192GCM: jose.EncA192GCM,
		jose.AlgA256GCM: jose.EncA256GCM,
	}
)

// JweDirectEncryptorAead implementation of JweDirectEncryptionEncryptor interface.
type JweDirectEncryptorAead struct {
	key        AeadEncryptionKey
	externalIV bool
}

// Encrypt encrypt and authenticate the given plaintext and AAD returning a compact JWE.
func (encryptor *JweDirectEncryptorAead) Encrypt(plaintext, aad []byte) (string, error) {
	var nonce []byte
	var err error
	if !encryptor.externalIV {
		nonce, err = encryptor.key.GenerateNonce()
		if err != nil {
			return "", err
		}
	}

	var blob *jose.Blob
	var customHeaderFields jose.JweCustomHeaderFields
	if len(aad) > 0 {
		blob = &jose.Blob{B: aad}
		customHeaderFields = jose.JweCustomHeaderFields{
			OtherAad: blob,
		}
	}

	// This encryptor intentionally implements the legacy (non-RFC7516-compliant) JWE format.
	jwe := &jose.Jwe{
		Header: jose.JweHeader{
			JwsHeader: jose.JwsHeader{
				Alg: jose.AlgDir,
				Kid: encryptor.key.Kid(),
			},
			Enc:                   gcmAlgToEncMap[encryptor.key.Algorithm()],
			JweCustomHeaderFields: customHeaderFields,
		},
		EncryptedKey: []byte{},
		Iv:           nonce,
		Plaintext:    plaintext,
	}
	if err = jwe.MarshalHeader(); err != nil {
		return "", err
	}

	if jwe.Ciphertext, jwe.Tag, err = encryptor.key.Seal(jose.KeyOpsEncrypt, jwe.Iv, jwe.Plaintext, jwe.MarshalledHeader); err != nil {
		return "", err
	}
	if encryptor.externalIV {
		/*
			If using an externally-generated IV this will have been returned in the tag field
			So we trim the tag field and update the IV field
		*/
		var throwawayNonceToGetLength []byte
		if throwawayNonceToGetLength, err = encryptor.key.GenerateNonce(); nil != err {
			return "", err
		}
		jwe.Iv = jwe.Tag[len(jwe.Tag)-len(throwawayNonceToGetLength):]
		jwe.Tag = jwe.Tag[:len(jwe.Tag)-len(throwawayNonceToGetLength)]
	}
	return jwe.Marshal(), nil
}

// NewJweDirectEncryptorAead construct an instance of a JweDirectEncryptorAead.
func NewJweDirectEncryptorAead(key AeadEncryptionKey, externalIV bool) *JweDirectEncryptorAead {
	return &JweDirectEncryptorAead{
		key:        key,
		externalIV: externalIV,
	}
}
