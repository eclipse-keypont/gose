// SPDX-FileCopyrightText: 2026 Thales Group and the gose Contributors
// SPDX-License-Identifier: MIT

package gose

import (
	"context"
	"time"

	"github.com/eclipse-keypont/gose/jose"
)

// JwtVerifierImpl implements the JWT Verification API
type JwtVerifierImpl struct {
	store TrustStore
	now   func() time.Time
}

// Verify the jwt and audience is valid
func (verifier *JwtVerifierImpl) Verify(jwt string, audience []string) (kid string, claims *jose.JwtClaims, err error) {
	// Bound before parsing: the token is attacker-supplied and the jose layer decodes
	// each segment into a fresh allocation.
	if len(jwt) > jose.MaxCompactSize {
		err = ErrInputTooLarge
		return
	}
	var token jose.Jwt
	var signed string
	if signed, err = token.Unmarshal(jwt); err != nil {
		return
	}

	// Authenticate the token before evaluating its claims: until the signature verifies,
	// the claims are attacker-supplied, and checking them first spends work on (and echoes)
	// whatever an unsigned token carries. The issuer is the one claim needed beforehand, to
	// select the trust store entry.

	// Though optional in the JWT spec we always require a Key ID to be present
	// to resist various known attacks.
	if len(token.Header.Kid) == 0 {
		err = ErrInvalidKid
		return
	}
	var key VerificationKey
	key, err = verifier.store.Get(context.Background(), token.Claims.Issuer, token.Header.Kid)
	if key == nil {
		err = ErrUnknownKey
		return
	}
	if err != nil {
		return
	}
	// Ensure algorithms match!
	if key.Algorithm() != token.Header.Alg {
		err = ErrInvalidAlgorithm
		return
	}
	if !key.Verify(jose.KeyOpsVerify, []byte(signed), token.Signature) {
		err = ErrInvalidSignature
		return
	}

	now := verifier.now().Unix()
	if token.Claims.NotBefore > now {
		err = ErrInvalidJwtTimeframe
		return
	}
	if token.Claims.Expiration <= now {
		err = ErrInvalidJwtTimeframe
		return
	}
	if !hasExpectedAudience(token.Claims.Audiences.Aud, audience) {
		// The error names neither the token's audiences nor the expected ones: the first
		// would echo token content into logs, the second describes the service.
		err = ErrNoExpectedAudience
		return
	}

	kid = key.Kid()
	claims = &token.Claims
	return
}

// hasExpectedAudience reports whether any of the token's audiences is one of the expected ones.
func hasExpectedAudience(tokenAudiences, expected []string) bool {
	want := make(map[string]struct{}, len(expected))
	for _, aud := range expected {
		want[aud] = struct{}{}
	}
	for _, aud := range tokenAudiences {
		if _, ok := want[aud]; ok {
			return true
		}
	}
	return false
}

// NewJwtVerifier creates a JWT Verifier for a given truststore
func NewJwtVerifier(ks TrustStore) *JwtVerifierImpl {
	return &JwtVerifierImpl{store: ks, now: time.Now}
}
