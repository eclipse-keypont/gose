// SPDX-FileCopyrightText: 2026 Thales Group and the gose Contributors
// SPDX-License-Identifier: MIT

// Package main demonstrates encrypting and decrypting a compact JWE using gose.
package main

import (
	"fmt"
	"os"

	"github.com/eclipse-keypont/gose"
	"github.com/eclipse-keypont/gose/jose"
)

var (
	keyOps = []jose.KeyOps{jose.KeyOpsDecrypt, jose.KeyOpsEncrypt}
)

const (
	secretData        = "This is a really secret thing"
	authenticatedData = "This data is authenticated and publicly readable"
)

func fail(err error) {
	fmt.Println(err.Error())
	os.Exit(1)
}

func main() {
	// Firstly we create an encryption key for encrypting data using a Direct Encryption JWE encryption scheme.
	generator := gose.AuthenticatedEncryptionKeyGenerator{}
	var jwk jose.Jwk
	key, jwk, err := generator.Generate(jose.AlgA256GCM, keyOps)
	if err != nil {
		fail(err)
	}
	marshalled, err := gose.JwkToString(jwk)
	if err != nil {
		fail(err)
	}
	fmt.Printf("Created encryption key JWK: %s\n", marshalled)

	// Create an encryptor using our key.
	encryptor := gose.NewJweDirectEncryptorAead(key, false)

	// Our encryptor accepts both secret data ti be encrypted as well as additional data to be included in the JWE as an
	// authenticated and non-repudiable value. The aad value is included in the JWE header in the _thales_aad field.
	jwe, err := encryptor.Encrypt([]byte(secretData), []byte(authenticatedData))
	if err != nil {
		fail(err)
	}
	fmt.Printf("Created JWE: %s\n", jwe)

	// Now we create a decryptor to decrypt and verify the authenticity of a previously created JWE.
	key, err = gose.NewAesGcmCryptorFromJwk(jwk, []jose.KeyOps{jose.KeyOpsDecrypt})
	if err != nil {
		fail(err)
	}
	decryptor := gose.NewJweDirectDecryptorAeadImpl([]gose.AeadEncryptionKey{key})

	// Decrypt a JWE blob verifying it's authenticity in the process.
	plaintext, aad, err := decryptor.Decrypt(jwe)
	if err != nil {
		fail(err)
	}

	fmt.Printf("Decrypted JWE plaintext: %s\n", string(plaintext))
	fmt.Printf("JWE Authenticated Data: %s\n", string(aad))
}
