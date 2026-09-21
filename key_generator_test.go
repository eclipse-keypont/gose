// SPDX-FileCopyrightText: 2026 Thales Group and the gose Contributors
// SPDX-License-Identifier: MIT

package gose

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/eclipse-keypont/gose/jose"
)

func BenchmarkRsaSigningKeyGenerator_Generate(b *testing.B) {
	setups := map[jose.Alg]int{
		jose.AlgRS256: 2048,
		jose.AlgRS384: 2048,
		jose.AlgRS512: 2048,
	}
	generator := new(RsaSigningKeyGenerator)

	for algo, length := range setups {
		b.Run(fmt.Sprintf("%v_%v", algo, length), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				_, _ = generator.Generate(algo, length, []jose.KeyOps{jose.KeyOpsSign})
			}
		})
	}
}

func BenchmarkECDSASigningKeyGenerator_Generate(b *testing.B) {
	setups := map[jose.Alg]int{
		jose.AlgES256: 256,
		jose.AlgES384: 384,
		jose.AlgES512: 512,
	}
	generator := new(ECDSASigningKeyGenerator)

	for algo, length := range setups {

		b.Run(fmt.Sprintf("%v_%v", algo, length), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				_, _ = generator.Generate(algo, []jose.KeyOps{jose.KeyOpsSign})
			}
		})
	}
}

func TestRSAGenerateSigningKeySucceeds(t *testing.T) {
	// Setup
	generator := new(RsaSigningKeyGenerator)

	cases := []struct {
		bits int
		alg  jose.Alg
	}{
		{
			bits: 2048,
			alg:  jose.AlgRS256,
		},
		{
			bits: 2048,
			alg:  jose.AlgRS384,
		},
		{
			bits: 2048,
			alg:  jose.AlgRS512,
		},
		{
			bits: 2048,
			alg:  jose.AlgPS256,
		},
		{
			bits: 2048,
			alg:  jose.AlgPS384,
		},
		{
			bits: 2048,
			alg:  jose.AlgPS512,
		},
	}

	// Act
	for _, test := range cases {
		key, err := generator.Generate(test.alg, test.bits, []jose.KeyOps{jose.KeyOpsSign})

		// Assert
		require.Nil(t, err)
		require.NotNil(t, key)
		jwk, err := key.Jwk()
		require.NoError(t, err)
		assert.Equal(t, test.alg, jwk.Alg())
	}
}

func TestECDSAGenerateSigningKeySucceeds(t *testing.T) {
	// Setup
	generator := new(ECDSASigningKeyGenerator)

	cases := []struct {
		bits int
		alg  jose.Alg
	}{
		{
			bits: 256,
			alg:  jose.AlgES256,
		},
		{
			bits: 384,
			alg:  jose.AlgES384,
		},
		{
			bits: 512,
			alg:  jose.AlgES512,
		},
	}

	// Act
	for _, test := range cases {
		key, err := generator.Generate(test.alg, []jose.KeyOps{jose.KeyOpsSign})

		// Assert
		require.Nil(t, err)
		require.NotNil(t, key)
		jwk, err := key.Jwk()
		require.NoError(t, err)
		assert.Equal(t, test.alg, jwk.Alg())
	}
}

func TestGenerateSigningKeyFailsWhenInvalidAlgorithm(t *testing.T) {
	// Setup
	generator := new(RsaSigningKeyGenerator)

	// Act
	key, err := generator.Generate(jose.AlgES256, 2048, []jose.KeyOps{jose.KeyOpsSign})

	// Assert
	assert.Nil(t, key)
	assert.Equal(t, ErrInvalidAlgorithm, err)
}

func TestGenerateSigningKeyFailsWhenInvalidKeySize(t *testing.T) {
	// Setup
	generator := new(RsaSigningKeyGenerator)

	// Act
	key, err := generator.Generate(jose.AlgRS256, 1024, []jose.KeyOps{jose.KeyOpsSign})

	// Assert
	assert.Nil(t, key)
	assert.Equal(t, ErrInvalidKeySize, err)
}

func TestGenerateSigningKeyFailsWhenInvalidOperation(t *testing.T) {
	// Setup
	testCase := [][]jose.KeyOps{
		{jose.KeyOpsVerify},
	}
	generator := new(RsaSigningKeyGenerator)

	for _, test := range testCase {
		// Act
		key, err := generator.Generate(jose.AlgRS256, 2048, test)

		// Assert
		assert.Nil(t, key)
		assert.Equal(t, ErrInvalidOperations, err)
	}
}

// TODO: redo these tests, as monkey patching doesn't seem to work here
//
//func TestGenerateSigningKeyFailsWhenGenerateKeyFails(t *testing.T) {
//	// Setup
//	generator := new(RsaSigningKeyGenerator)
//	expectedError := errors.New("Expected error")
//	defer  monkey.Patch(rsa.GenerateKey, func(reader io.Reader, bits int) (*rsa.PrivateKey, error) {
//		t.Log("patching")
//		return nil, expectedError
//	}).Unpatch()
//
//	// Act
//	k, e := generator.Generate(jose.AlgRS256, 2048, []jose.KeyOps{jose.KeyOpsSign})
//
//	// Assert
//	require.Nil(t, k)
//	require.Error(t, expectedError, e)
//}
//
//func TestGenerateSigningKeyFailsWhenExponentTooBig(t *testing.T) {
//	// Setup
//	fakeKey := rsa.PrivateKey{}
//	fakeKey.E = math.MaxInt64
//	defer monkey.PatchInstanceMethod(reflect.TypeOf(&fakeKey), "Validate",
//		func(*rsa.PrivateKey) error { return nil },
//	).Unpatch()
//	generator := new(RsaSigningKeyGenerator)
//	defer monkey.Patch(rsa.GenerateKey, func(reader io.Reader, bits int) (*rsa.PrivateKey, error) {
//		var k rsa.PrivateKey
//		k.E = math.MaxInt64
//		return &k, nil
//	}).Unpatch()
//
//	// Act
//	k, e := generator.Generate(jose.AlgRS256, 2048, []jose.KeyOps{jose.KeyOpsSign})
//
//	// Assert
//	require.Error(t, ErrInvalidExponent, e)
//	require.Nil(t, k)
//
//}

func TestAuthenticatedEncryptionKeyGenerator_Generate_InvalidAlgorithm(t *testing.T) {
	generator := &AuthenticatedEncryptionKeyGenerator{}

	key, jwk, err := generator.Generate(jose.AlgES256, []jose.KeyOps{})

	assert.Nil(t, key)
	assert.Nil(t, jwk)
	assert.Equal(t, ErrInvalidAlgorithm, err)
}

func TestAuthenticatedEncryptionKeyGenerator_Generate_NoValidOperations(t *testing.T) {
	generator := &AuthenticatedEncryptionKeyGenerator{}

	key, jwk, err := generator.Generate(jose.AlgA256GCM, []jose.KeyOps{})

	assert.Nil(t, key)
	assert.Nil(t, jwk)
	assert.Equal(t, ErrInvalidOperations, err)
}

func TestAuthenticatedEncryptionKeyGenerator_Generate(t *testing.T) {
	generator := &AuthenticatedEncryptionKeyGenerator{}

	for _, alg := range []jose.Alg{jose.AlgA128GCM, jose.AlgA192GCM, jose.AlgA256GCM} {

		key, jwk, err := generator.Generate(alg, []jose.KeyOps{jose.KeyOpsDecrypt, jose.KeyOpsEncrypt})

		assert.NotNil(t, key)
		assert.NotNil(t, jwk)
		assert.NoError(t, err)
	}
}
