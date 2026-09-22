// SPDX-FileCopyrightText: 2026 Thales Group and the gose Contributors
// SPDX-License-Identifier: MIT

package gose

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"testing"

	"crypto"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/eclipse-keypont/gose/jose"
)

type MockedJwk struct {
	mock.Mock
}

func (jwk *MockedJwk) Alg() jose.Alg {
	args := jwk.Called()
	return args.Get(0).(jose.Alg)
}

func (jwk *MockedJwk) SetAlg(alg jose.Alg) {
	jwk.Called(alg)
}

func (jwk *MockedJwk) Ops() []jose.KeyOps {
	args := jwk.Called()
	return args.Get(0).([]jose.KeyOps)
}

func (jwk *MockedJwk) SetOps(ops []jose.KeyOps) {
	jwk.Called(ops)
}

func (jwk *MockedJwk) Kid() string {
	args := jwk.Called()
	return args.String(0)
}

func (jwk *MockedJwk) SetKid(kid string) {
	jwk.Called(kid)
}

func (jwk *MockedJwk) Kty() string {
	args := jwk.Called()
	return args.String(0)
}

func (jwk *MockedJwk) SetKty(kty string) {
	jwk.Called(kty)
}

func (jwk *MockedJwk) Use() jose.KeyUse {
	args := jwk.Called()
	return args.Get(0).(jose.KeyUse)
}

func (jwk *MockedJwk) SetUse(use jose.KeyUse) {
	jwk.Called(use)
}

func (jwk *MockedJwk) X5C() []*x509.Certificate {
	args := jwk.Called()
	return args.Get(0).([]*x509.Certificate)
}

func (jwk *MockedJwk) SetX5C(certs []*x509.Certificate) {
	jwk.Called(certs)
}

type MockedSigner struct {
	mock.Mock
}

func (signer *MockedSigner) Key() crypto.Signer {
	args := signer.Called()
	return args.Get(0).(crypto.Signer)
}

func (signer *MockedSigner) Algorithm() jose.Alg {
	args := signer.Called()
	return args.Get(0).(jose.Alg)
}

func (signer *MockedSigner) Jwk() (jose.Jwk, error) {
	args := signer.Called()
	return args.Get(0).(jose.Jwk), args.Error(1)
}

func (signer *MockedSigner) Sign(operation jose.KeyOps, payload []byte) (signature []byte, err error) {
	args := signer.Called(operation, payload)
	sig := args.Get(0)
	err = args.Error(1)
	if sig != nil {
		signature = sig.([]byte)
	}
	return
}

func (signer *MockedSigner) Marshal() (string, error) {
	args := signer.Called()
	return args.String(0), args.Error(1)
}

func (signer *MockedSigner) MarshalPem() (string, error) {
	args := signer.Called()
	return args.String(0), args.Error(1)
}

func (signer *MockedSigner) Certificates() []*x509.Certificate {
	args := signer.Called()
	return args.Get(0).([]*x509.Certificate)
}

func (signer *MockedSigner) Kid() string {
	args := signer.Called()
	return args.Get(0).(string)
}

func (signer *MockedSigner) Verifier() (VerificationKey, error) {
	args := signer.Called()
	return args.Get(0).(VerificationKey), args.Error(1)
}

func TestNewSigningKey_Succeeds(t *testing.T) {
	// Setup
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	jwk, err := JwkFromPrivateKey(k, []jose.KeyOps{jose.KeyOpsSign}, nil)
	require.NoError(t, err)

	// Act
	signer, err := NewSigningKey(jwk, []jose.KeyOps{jose.KeyOpsSign})

	// Assert
	require.NoError(t, err)
	require.NotNil(t, signer)
}

func TestNewSigningKey_FailsWhenInvalidOperations(t *testing.T) {
	// Setup
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	testCase := [][]jose.KeyOps{
		{jose.KeyOpsVerify},
		{jose.KeyOpsSign, jose.KeyOpsVerify},
	}
	for _, test := range testCase {
		jwk, err := JwkFromPrivateKey(k, []jose.KeyOps{jose.KeyOpsSign}, nil)
		require.NoError(t, err)

		// Act
		signer, err := NewSigningKey(jwk, test)

		// Assert
		require.Nil(t, signer)
		require.Equal(t, ErrInvalidOperations, err)
	}
}

func TestNewSigningKey_FailsWhenInvalidJwk(t *testing.T) {
	// Setup
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	jwk, err := JwkFromPublicKey(k.Public(), []jose.KeyOps{jose.KeyOpsSign}, nil)
	require.NoError(t, err)

	// Act
	signer, err := NewSigningKey(jwk, []jose.KeyOps{jose.KeyOpsSign})

	// Assert
	require.Error(t, err)
	require.Nil(t, signer)
}

// TestNewSigningKey_RejectsAlgWithoutSignerOpts pins the nil-dereference fix.
// LoadPrivateKey admits the RSAES-OAEP algorithms because decryption keys share it,
// but they have no entry in algToOptsMap. A JWK labelled "RSA-OAEP" with a "sign"
// key_op was accepted by NewSigningKey and then crashed in Sign with a nil-pointer
// dereference on HashFunc(). It is refused at construction now, and Sign itself
// returns ErrInvalidAlgorithm should such a key be built another way.
func TestNewSigningKey_RejectsAlgWithoutSignerOpts(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	jwk, err := JwkFromPrivateKey(key, []jose.KeyOps{jose.KeyOpsSign}, nil)
	require.NoError(t, err)

	for _, alg := range []jose.Alg{jose.AlgRSAOAEP, jose.AlgRSAOAEPSHA2, jose.Alg("bogus")} {
		jwk.SetAlg(alg)
		sk, err := NewSigningKey(jwk, nil)
		require.ErrorIs(t, err, ErrInvalidAlgorithm, "alg %s", alg)
		require.Nil(t, sk)
	}

	// Sign on a decryption key (RSA-OAEP, which legitimately has no signer opts) must
	// error, not panic, even when its key_ops happen to permit "sign".
	jwk.SetAlg(jose.AlgRSAOAEP)
	jwk.SetOps([]jose.KeyOps{jose.KeyOpsSign, jose.KeyOpsDecrypt})
	dec, err := NewRsaDecryptionKey(jwk)
	require.NoError(t, err)
	require.NotPanics(t, func() {
		_, err = dec.Sign(jose.KeyOpsSign, []byte("data"))
	})
	require.ErrorIs(t, err, ErrInvalidAlgorithm)
}
