// SPDX-FileCopyrightText: 2026 Thales Group and the gose Contributors
// SPDX-License-Identifier: MIT

package gose

import (
	"encoding/json"
	"log"
	"time"

	"github.com/google/uuid"

	"github.com/eclipse-keypont/gose/jose"
)

var _ JwtSigner = (*JwtSignerImpl)(nil)

// JwtSignerImpl JWT implementation
type JwtSignerImpl struct {
	key    SigningKey
	issuer string
}

// Issuer returns issuer of JWT
func (signer *JwtSignerImpl) Issuer() string {
	return signer.issuer
}

// Sign claims to a JWT string
func (signer *JwtSignerImpl) Sign(claims *jose.SettableJwtClaims, untyped map[string]interface{}) (string, error) {
	var encodedUntyped jose.UntypedClaims
	if untyped != nil {
		encodedUntyped = make(jose.UntypedClaims, len(untyped))
		for k, v := range untyped {
			encoded, err := json.Marshal(v)
			if err != nil {
				return "", err
			}
			encodedUntyped[k] = encoded
		}
	}
	jwt := jose.Jwt{
		Header: jose.JwsHeader{
			Alg: signer.key.Algorithm(),
			Kid: signer.key.Kid(),
			Typ: jose.JwtType,
		},
		Claims: jose.JwtClaims{
			AutomaticJwtClaims: jose.AutomaticJwtClaims{
				IssuedAt: time.Now().Unix(),
				Issuer:   signer.issuer,
				JwtID:    uuid.New().String(),
			},
			SettableJwtClaims: *claims,
			UntypedClaims:     encodedUntyped,
		},
	}
	toBeSigned, err := jwt.MarshalBody()
	if err != nil {
		return "", err
	}
	signature, err := signer.key.Sign(jose.KeyOpsSign, []byte(toBeSigned))
	if err != nil {
		return "", err
	}
	jwt.Signature = make([]byte, len(signature))
	if count := copy(jwt.Signature, signature); count != len(signature) {
		// This should never happen!
		log.Panic("failed to copy all signature bytes")
	}
	return jose.MarshalJws(toBeSigned, jwt.Signature), nil
}

// NewJwtSigner returns a JWT Signer for a issuer and jwk
func NewJwtSigner(issuer string, key SigningKey) *JwtSignerImpl {
	return &JwtSignerImpl{key: key, issuer: issuer}
}
