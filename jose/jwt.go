// SPDX-FileCopyrightText: 2026 Thales Group and the gose Contributors
// SPDX-License-Identifier: MIT

package jose

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"math"
	"reflect"
	"strings"
)

// Standard JWT claim names that cannot be used as untyped keys.
var reservedJwtClaims = map[string]bool{
	"iss": true,
	"iat": true,
	"jti": true,
	"sub": true,
	"aud": true,
	"exp": true,
	"nbf": true,
}

// AutomaticJwtClaims represent standard JWT claims that should not generally be set by a caller.
// For example the iat (issued-at) claim should only be set by a signer not the caller who requests
// the JWT.
type AutomaticJwtClaims struct {
	Issuer   string `json:"iss,omitempty"`
	IssuedAt int64  `json:"iat,omitempty"`
	JwtID    string `json:"jti,omitempty"`
}

// SettableJwtClaims are claims generally requested by a caller and not a signer.
type SettableJwtClaims struct {
	Subject    string    `json:"sub,omitempty"`
	Audiences  Audiences `json:"aud,omitempty"`
	Expiration int64     `json:"exp,omitempty"`
	NotBefore  int64     `json:"nbf,omitempty"`
}

// UntypedClaims for non-standard clains
type UntypedClaims map[string]json.RawMessage

// JwtClaims claims for a JWT
type JwtClaims struct {
	AutomaticJwtClaims
	SettableJwtClaims
	UntypedClaims
}

// unmarshalClaims unmarshal typed claims into the struct |into|
func unmarshalTypedClaims(claims map[string]json.RawMessage, into interface{}) (err error) {
	/* Loop through known claims extracting values as appropriate. */
	auto := reflect.TypeOf(into).Elem()
	for i := 0; i < auto.NumField(); i++ {
		field := reflect.ValueOf(into).Elem().Field(i)
		// TODO: write a proper json tag parser when needed. All our known claims have a consistent struct tag format.
		if tag, exists := auto.Field(i).Tag.Lookup("json"); exists {
			values := strings.Split(tag, ",")
			if len(values) < 1 {
				// should never happen
				slog.Error("broken json struct tag")
				return fmt.Errorf("broken json struct tag")
			}
			name := values[0]
			if value, exists := claims[name]; exists {
				if !field.CanAddr() {
					// should never happen
					slog.Error("broken json struct type, must be addressable")
					return fmt.Errorf("broken json struct type, must be addressable")
				}
				if err = json.Unmarshal(value, field.Addr().Interface()); err != nil {
					return
				}
				// Remove claim we have consumed.
				delete(claims, name)
			}
		}
	}
	return

}

// UnmarshalJSON implements json.Unmarshaler interface method.
func (c *JwtClaims) UnmarshalJSON(data []byte) (err error) {
	claims := make(map[string]json.RawMessage)
	if err = json.Unmarshal(data, &claims); err != nil {
		return
	}
	/* Decode typed claims. */
	if err = unmarshalTypedClaims(claims, &c.AutomaticJwtClaims); err != nil {
		return
	}
	if err = unmarshalTypedClaims(claims, &c.SettableJwtClaims); err != nil {
		return
	}
	// All remaining claims
	c.UntypedClaims = claims
	return
}

// UnmarshalCustomClaim Unmarshals a custom claim. A Claim that do not exist is unset but no error is returned.
func (c *JwtClaims) UnmarshalCustomClaim(name string, claim interface{}) error {
	targetClaim, ok := c.UntypedClaims[name]
	if ok {
		if err := json.Unmarshal(targetClaim, claim); err != nil {
			return err
		}
	}
	return nil
}

// MarshalJSON implements json.Marshaler interface method.
//
// Claim names are merged into a map rather than into a dynamically built struct.
// The struct approach (reflect.StructOf with a synthesised "A"+name field) panicked
// on any claim name that is not a valid Go identifier suffix — which includes the
// URL-namespaced names that OIDC mandates for custom claims, e.g.
// "https://example.com/roles" — and on names colliding with the embedded field
// names. A map has no such constraint and round-trips every name JSON permits.
func (c *JwtClaims) MarshalJSON() (dst []byte, err error) {
	// Temporary type and instance. Note the use of references.
	output := struct {
		*AutomaticJwtClaims
		*SettableJwtClaims
	}{
		AutomaticJwtClaims: &c.AutomaticJwtClaims,
		SettableJwtClaims:  &c.SettableJwtClaims,
	}

	// Marshal the typed claims first, then decompose them into the output map so the
	// typed and untyped halves can be merged in a single object.
	var typed []byte
	if typed, err = json.Marshal(output); err != nil {
		return nil, err
	}
	merged := map[string]json.RawMessage{}
	if err = json.Unmarshal(typed, &merged); err != nil {
		return nil, err
	}

	for k, v := range c.UntypedClaims {
		// Validate untyped fields do not clash with standard JWT claims.
		if _, invalid := reservedJwtClaims[k]; invalid {
			return nil, ErrJwkReservedClaimName
		}
		merged[k] = v
	}
	return json.Marshal(merged)
}

// Jwt defines a Jave web token
type Jwt struct {
	Header    JwsHeader
	Claims    JwtClaims
	Signature []byte
}

// Verify JWT is valid or error
func (jwt *Jwt) Verify() error {
	if jwt.Header.Typ != JwtType {
		/* Not a JWT. */
		return ErrJwtFormat
	}
	if jwt.Header.Cty != "" && jwt.Header.Cty != JwtType {
		return ErrJwtFormat

	}
	// RFC 7515 §4.1.11: extension header parameters listed in "crit" must be understood
	// and processed, otherwise the JWS is invalid. gose implements no extensions, so any
	// non-empty "crit" is fatal. Enforced here rather than in the gose verifier so every
	// path through the jose layer inherits it.
	if len(jwt.Header.Crit) > 0 {
		return ErrCritHeaderNotSupported
	}
	for k := range jwt.Claims.UntypedClaims {
		if _, invalid := reservedJwtClaims[k]; invalid {
			return ErrJwkReservedClaimName
		}
	}
	return nil
}

// MarshalBody representation of the JWT Header and Claims.
func (jwt *Jwt) MarshalBody() (body string, err error) {
	if err = jwt.Verify(); err != nil {
		return
	}
	jws := Jws{
		Header:  &jwt.Header,
		Payload: &jwt.Claims,
	}
	return jws.MarshalBody()
}

// Unmarshal string to JWT body, or error
func (jwt *Jwt) Unmarshal(src string) (body string, err error) {
	/* Compact JWT encoding. */
	/* Default Exp field to maximum in case it is not set. */
	jwt.Claims.Expiration = math.MaxInt64
	jws := Jws{
		Header:  &jwt.Header,
		Payload: &jwt.Claims,
	}
	if body, err = jws.Unmarshal(src); err != nil {
		return
	}
	// Ick some copying here but do we really care?
	jwt.Signature = make([]byte, len(jws.Signature))
	_ = copy(jwt.Signature, jws.Signature)
	if err = jwt.Verify(); err != nil {
		body = ""
		return
	}
	return
}
