// SPDX-FileCopyrightText: 2026 Thales Group and the gose Contributors
// SPDX-License-Identifier: MIT

package gose

import (
	"encoding/binary"
	"fmt"

	"github.com/eclipse-keypont/gose/jose"
)

// JweDirectDecryptorBlock implements decryption of a compact JWE using direct key agreement with a block cipher.
type JweDirectDecryptorBlock struct {
	aesKey      BlockEncryptionKey
	jweVerifier JweHmacVerifierImpl
}

// Decrypt and verify the given JWE returning the plaintext.
// never return a non nil aad. aad is just here to satisfy the JweDecryptor interface
func (decryptor *JweDirectDecryptorBlock) Decrypt(marshalledJwe string) (plaintext, aad []byte, err error) {
	// The following steps respect the RFC7516 decryption instructions :
	// https://datatracker.ietf.org/doc/html/rfc7516
	// The message decryption process is the reverse of the encryption
	//   process.  The order of the steps is not significant in cases where
	//   there are no dependencies between the inputs and outputs of the
	//   steps.  If any of these steps fail, the encrypted content cannot be
	//   validated.
	var jwe jose.JweRfc7516Compact
	if err = jwe.Unmarshal(marshalledJwe); err != nil {
		return nil, nil, fmt.Errorf("error unmarshalling the jwe: %w", err)
	}
	// check the algorithm in header
	if jwe.ProtectedHeader.Alg != decryptor.aesKey.Algorithm() {
		return nil, nil, fmt.Errorf("error checking the JWE protected header's algorithm. algorithm is '%v' but expected is '%v'", jwe.ProtectedHeader.Alg, decryptor.aesKey.Algorithm())
	}
	// check the keys for direct encryption
	if jwe.ProtectedHeader.Kid != decryptor.aesKey.Kid() {
		return nil, nil, fmt.Errorf("error checking the Key ID for decryption. ID is '%v' but expected is '%v'", jwe.ProtectedHeader.Kid, decryptor.aesKey.Kid())
	}

	// INTEGRITY CHECK before decryption
	integrity, err := decryptor.jweVerifier.VerifyCompact(jwe)
	if err != nil {
		return nil, nil, err
	}
	if !integrity {
		return nil, nil, fmt.Errorf("error corrupted jwe : integrity check failed")
	}

	// decryption
	if jwe.ProtectedHeader.Zip != "" {
		err = ErrZipCompressionNotSupported
		return
	}
	plaintextBlock := decryptor.aesKey.Open(jwe.Ciphertext)

	// get the size of the final plaintext
	//input, err := jwe.ProtectedHeader.OtherAad.MarshalJSON()
	if jwe.ProtectedHeader.OtherAad == nil {
		return nil, nil, fmt.Errorf("error decoding plaintext length: missing length header")
	}
	data := jwe.ProtectedHeader.OtherAad.B
	// Validate before use: a truncated field panics BigEndian.Uint64; an oversized
	// value causes OOM; nil OtherAad was already rejected above.
	if len(data) < 8 {
		return nil, nil, fmt.Errorf("error decoding plaintext length: header field too short")
	}
	plaintextLength := binary.BigEndian.Uint64(data)
	if plaintextLength > uint64(len(plaintextBlock)) {
		return nil, nil, fmt.Errorf("error decoding plaintext: declared length %d exceeds decrypted length %d", plaintextLength, len(plaintextBlock))
	}
	plaintext = make([]byte, plaintextLength)
	copy(plaintext, plaintextBlock[:plaintextLength])

	return plaintext, nil, nil
}

// NewJweDirectDecryptorBlock create a new instance of a JweDirectDecryptorBlock.
func NewJweDirectDecryptorBlock(aesKey BlockEncryptionKey, hmacKey HmacKey) *JweDirectDecryptorBlock {
	// Create map out of our list of keys. The map is keyed in Kid.
	decryptor := &JweDirectDecryptorBlock{
		aesKey:      aesKey,
		jweVerifier: JweHmacVerifierImpl{hmacKey: hmacKey},
	}
	return decryptor
}
