// SPDX-FileCopyrightText: 2026 Thales Group and the gose Contributors
// SPDX-License-Identifier: MIT

package gose

import (
	"context"
	"fmt"
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
	var token jose.Jwt
	var signed string
	if signed, err = token.Unmarshal(jwt); err != nil {
		return
	}
	now := verifier.now().Unix()
	seen := []string{}
	if token.Claims.NotBefore > now {
		err = ErrInvalidJwtTimeframe
		return
	}
	if token.Claims.Expiration <= now {
		err = ErrInvalidJwtTimeframe
		return
	}
	if len(token.Claims.Audiences.Aud) == 0 || len(audience) == 0 {
		err = &InvalidFormat{fmt.Sprintf("no expected audience | expected %s | seen %s", audience, seen)}
		return
	}

	// For debugging you may want to see the details of the expected and observed audiences
	// Check at least 1 audience exists
	found := false
	for _, candidate := range audience {
		for _, aud := range token.Claims.Audiences.Aud {
			seen = append(seen, aud)
			found = found || candidate == aud
		}
	}
	if !found {
		err = &InvalidFormat{fmt.Sprintf("no expected audience | expected %s | seen %s", audience, seen)}
		return
	}

	// Though optional in the JWT spec we always require a Key ID to be present
	// to resist various known attacks.
	if len(token.Header.Kid) == 0 {
		err = ErrInvalidKid
		return
	}
	if len(token.Header.Kid) > 0 {
		var key VerificationKey
		key, err = verifier.store.Get(context.Background(), token.Claims.Issuer, token.Header.Kid)
		if key == nil {
			err = ErrUnknownKey
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
		kid = key.Kid()
	}

	claims = &token.Claims
	return
}

// NewJwtVerifier creates a JWT Verifier for a given truststore
func NewJwtVerifier(ks TrustStore) *JwtVerifierImpl {
	return &JwtVerifierImpl{store: ks, now: time.Now}
}
