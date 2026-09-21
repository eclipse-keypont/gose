// SPDX-FileCopyrightText: 2026 Thales Group and the gose Contributors
// SPDX-License-Identifier: MIT

package gose

import (
	"log"
	"testing"

	"github.com/stretchr/testify/mock"

	"github.com/eclipse-keypont/gose/jose"

	"github.com/stretchr/testify/assert"
)

type authenticatedEncryptionKeyMock struct {
	mock.Mock
}

func (encryptor *authenticatedEncryptionKeyMock) GenerateNonce() ([]byte, error) {
	args := encryptor.Called()
	return args.Get(0).([]byte), args.Error(1)
}

func (encryptor *authenticatedEncryptionKeyMock) Seal(operation jose.KeyOps, nonce, plaintext, aad []byte) (ciphertext, tag []byte, err error) {
	args := encryptor.Called(operation, nonce, plaintext, aad)
	return args.Get(0).([]byte), args.Get(1).([]byte), args.Error(2)
}

func (encryptor *authenticatedEncryptionKeyMock) Open(operation jose.KeyOps, nonce, ciphertext, aad, tag []byte) (plaintext []byte, err error) {
	args := encryptor.Called(operation, nonce, ciphertext, aad, tag)
	return args.Get(0).([]byte), args.Error(1)
}

func (encryptor *authenticatedEncryptionKeyMock) Algorithm() jose.Alg {
	args := encryptor.Called()
	return args.Get(0).(jose.Alg)
}

func (encryptor *authenticatedEncryptionKeyMock) Kid() string {
	args := encryptor.Called()
	return args.String(0)
}

func (encryptor *authenticatedEncryptionKeyMock) Jwk() (jose.Jwk, error) {
	args := encryptor.Called()
	return args.Get(0).(jose.Jwk), args.Error(1)
}

func (encryptor *authenticatedEncryptionKeyMock) Marshal() (string, error) {
	args := encryptor.Called()
	return args.String(0), args.Error(1)
}

func TestNewJweEncryptorImpl(t *testing.T) {
	keyMock := &authenticatedEncryptionKeyMock{}
	encryptor := NewJweDirectEncryptorAead(keyMock, false)
	assert.NotNil(t, encryptor)
}

func TestJweDirectEncryptionEncryptorImpl_Encrypt(t *testing.T) {
	keyMock := &authenticatedEncryptionKeyMock{}
	keyMock.On("GenerateNonce").Return([]byte("nonce"), nil).Once()
	keyMock.On("Kid").Return("unique").Once()
	keyMock.On("Algorithm").Return(jose.AlgA256GCM).Once()
	keyMock.On("Seal", jose.KeyOpsEncrypt, []byte("nonce"), []byte("something"), mock.Anything).Return([]byte("encrypted"), []byte("tag"), nil).Once()

	encryptor := NewJweDirectEncryptorAead(keyMock, false)

	jwe, err := encryptor.Encrypt([]byte("something"), []byte("else"))
	assert.NoError(t, err)
	assert.NotEmpty(t, jwe)

	keyMock.AssertExpectations(t)
}

func TestExampleJweDirectEncryptionEncryptorImpl_EncryptDecrypt(_ *testing.T) {
	// First create a key which we use to encrypt and authenticate data.
	generator := &AuthenticatedEncryptionKeyGenerator{}
	cryptor, _, err := generator.Generate(jose.AlgA256GCM, []jose.KeyOps{jose.KeyOpsEncrypt, jose.KeyOpsDecrypt})
	if err != nil {
		panic(err)
	}

	// Now to encrypt and authenticate something .
	toEncrypt := []byte("some_data_to_encrypt")
	aad := []byte("some_data_to_authenticate")

	// Create a JWE cryptor
	jweEncryptor := NewJweDirectEncryptorAead(cryptor, false)

	// Now encrypt
	jwe, err := jweEncryptor.Encrypt(toEncrypt, aad)
	if err != nil {
		panic(err)
	}

	// print our JWE
	log.Printf("Created JWE: %s", jwe)

	// Now to decrypt
	jweDecryptor := NewJweDirectDecryptorAeadImpl([]AeadEncryptionKey{cryptor})

	recoveredPlaintext, recoveredAad, err := jweDecryptor.Decrypt(jwe)
	if err != nil {
		panic(err)
	}
	log.Printf("Recovered plaintext \"%s\" and AAD \"%s\"", string(recoveredPlaintext), string(recoveredAad))
}
