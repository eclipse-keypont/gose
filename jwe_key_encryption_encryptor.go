// SPDX-FileCopyrightText: 2026 Thales Group and the gose Contributors
// SPDX-License-Identifier: MIT

package gose

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rsa"
	"fmt"
	"io"

	"github.com/eclipse-keypont/gose/jose"
)

const cekSize uint8 = 32

const ivSize uint8 = 12

const cekAlgorithm = jose.AlgA256GCM

// JweRsaKeyEncryptionEncryptorImpl implements RSA Key Encryption CEK mode.
type JweRsaKeyEncryptionEncryptorImpl struct {
	rsaPublicKey *rsa.PublicKey
	rsaPublicKid string
	rsaAlg       jose.Alg
	randomSource io.Reader
}

// Encrypt encrypts the given plaintext into a compact JWE.
// The Content Encryption Key is encrypted to the recipient using the RSAES-OAEP algorithm to
// produce the JWE Encrypted Key.
// Authenticated encryption is performed on the plaintext using the AES GCM algorithm with a 256-bit
// key to produce the ciphertext and the Authentication Tag.
//
// oaepHash selects the OAEP digest and therefore the "alg" advertised in the protected
// header: crypto.SHA1 produces "RSA-OAEP" and crypto.SHA256 produces "RSA-OAEP-256", per
// RFC 7518 §4.3. Any other digest is rejected, because RFC 7518 registers no "alg" value
// that would describe the result to a recipient.
func (e *JweRsaKeyEncryptionEncryptorImpl) Encrypt(plaintext []byte, oaepHash crypto.Hash) (jwe string, err error) {
	// The header must name the digest actually used to wrap the CEK, otherwise a
	// conformant recipient derives the wrong OAEP parameters and decryption fails.
	oaepAlg, ok := OaepAlgFromHash(oaepHash)
	if !ok {
		return "", fmt.Errorf("%w: no RFC 7518 RSAES-OAEP algorithm for digest %v", ErrInvalidAlgorithm, oaepHash)
	}

	// create the protected header
	// {"alg":"RSA-OAEP-256","enc":"A256GCM"}
	protectedHeader := e.makeJweProtectedHeader(oaepAlg)

	// generate the 256-bit CEK, 32 bytes long
	cek := make([]byte, cekSize)
	if _, err = e.randomSource.Read(cek); err != nil {
		return "", fmt.Errorf("unable to read random source to generate the CEK: %w", err)
	}

	// encrypt the CEK using the recipient public key and RSAES OAEP
	// SHA1 is still safe when used in the construction of OAEP.
	encryptedCEK, err := rsa.EncryptOAEP(oaepHash.New(), e.randomSource, e.rsaPublicKey, cek, nil)
	if err != nil {
		return "", fmt.Errorf("failed to encrypt CEK: %w", err)
	}

	// generate a random 96-bit initialization vector
	iv := make([]byte, ivSize)
	if _, err = e.randomSource.Read(iv); err != nil {
		return "", fmt.Errorf("unable to read random source to generate the IV: %w", err)
	}

	// Create AAD equal to ASCII(BASE64URL(UTF8(JWE Protected Header))).
	var aad []byte
	if aad, err = protectedHeader.MarshalProtectedHeader(); err != nil {
		return "", fmt.Errorf("error marshalling the JWE Header: %w", err)
	}

	// encrypt the plaintext using the cek
	var blockCipher cipher.Block
	blockCipher, err = aes.NewCipher(cek)
	if err != nil {
		return "", fmt.Errorf("error creating AES cipher: %w", err)
	}
	var aesGCM cipher.AEAD
	aesGCM, err = cipher.NewGCM(blockCipher)
	if err != nil {
		return "", fmt.Errorf("error creating GCM: %w", err)
	}
	var aesGCMCryptor AeadEncryptionKey
	if aesGCMCryptor, err = NewAesGcmCryptor(aesGCM, e.randomSource, "", cekAlgorithm, []jose.KeyOps{jose.KeyOpsEncrypt}); err != nil {
		return "", fmt.Errorf("error creating AES GCM Cryptor: %w", err)
	}
	ciphertext, tag, err := aesGCMCryptor.Seal(jose.KeyOpsEncrypt, iv, plaintext, aad)
	if err != nil {
		return "", fmt.Errorf("error encrypting the plaintext: %w", err)
	}

	// create the compact representation of the jwe using the parameters above
	jweData := &jose.JweRfc7516Compact{
		ProtectedHeader:      *protectedHeader,
		EncryptedKey:         encryptedCEK,
		InitializationVector: iv,
		Ciphertext:           ciphertext,
		AuthenticationTag:    tag,
	}
	if jwe, err = jweData.Marshal(); err != nil {
		return "", fmt.Errorf("error marshalling the JWE: %w", err)
	}

	return
}

// makeJweProtectedHeader builds the JWE structure.
// oaepAlg is the RFC 7518 §4.3 algorithm matching the digest used to wrap the CEK; it is
// authoritative over the recipient key's own "alg", which names only the OAEP family.
func (e *JweRsaKeyEncryptionEncryptorImpl) makeJweProtectedHeader(oaepAlg jose.Alg) *jose.JweProtectedHeader {
	return &jose.JweProtectedHeader{
		JwsHeader: jose.JwsHeader{
			// "RSA-OAEP" (SHA-1) or "RSA-OAEP-256" (SHA-256)
			Alg: oaepAlg,
			Kid: e.rsaPublicKid,
			Typ: "JWT",
			Cty: "JWT",
		},
		// AlgA256GCM Alg = "A256GCM"
		Enc: cbcAlgToEncMap[cekAlgorithm],
	}
}

// NewJweRsaKeyEncryptionEncryptorImpl returns an instance of JweRsaKeyEncryptionEncryptorImpl configured with the given
// JWK.
// rsaPublicKeyRecipient is the jwk describing the public key that will be used to encrypt the CEK.
// randomSource is the random generator used by :
//   - the RSA OAEP algorithm for entropy source for each encryption operation on CEKs
//   - the encryption of the data performed by the CEK with AES GCM algorithm, for the IV
func NewJweRsaKeyEncryptionEncryptorImpl(rsaPublicKeyRecipient jose.Jwk, randomSource io.Reader) (*JweRsaKeyEncryptionEncryptorImpl, error) {
	// check if required operation is supported
	if !isSubset(rsaPublicKeyRecipient.Ops(), []jose.KeyOps{jose.KeyOpsEncrypt}) {
		return nil, ErrInvalidOperations
	}
	// create the asymmetric public key structure from the recipient
	kek, err := LoadPublicKey(rsaPublicKeyRecipient, validEncryptionOpts)
	if err != nil {
		return nil, err
	}
	// parse for rsa
	rsaKek, ok := kek.(*rsa.PublicKey)
	if !ok {
		return nil, ErrInvalidKeyType
	}
	// an RSA key is not enough: it must be an RSAES-OAEP key rather than, say, an RS256
	// signing key. Which of the two OAEP variants applies is chosen per-operation by the
	// digest passed to Encrypt.
	if !isRsaOaepAlg(rsaPublicKeyRecipient.Alg()) {
		return nil, ErrInvalidAlgorithm
	}

	return &JweRsaKeyEncryptionEncryptorImpl{
		rsaPublicKey: rsaKek,
		rsaAlg:       rsaPublicKeyRecipient.Alg(),
		rsaPublicKid: rsaPublicKeyRecipient.Kid(),
		randomSource: randomSource,
	}, nil
}
