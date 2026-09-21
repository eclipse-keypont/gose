// SPDX-FileCopyrightText: 2026 Thales Group and the gose Contributors
// SPDX-License-Identifier: MIT

package jose

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// compactJwt assembles an unsigned compact JWT with the given header and claims JSON.
func compactJwt(header, claims string) string {
	b64 := base64.RawURLEncoding.EncodeToString
	return strings.Join([]string{
		b64([]byte(header)), b64([]byte(claims)), b64([]byte("placeholder")),
	}, ".")
}

// JwtClaims.MarshalJSON built a struct at runtime via reflect.StructOf, naming each
// untyped claim "A"+claimName. reflect.StructOf panics when a field name is not a valid
// Go identifier, which is true of every URL-namespaced claim name — the convention OIDC
// mandates for custom claims. The panic escaped encoding/json's recover and killed the
// goroutine.
func TestJwtClaimsMarshalHandlesNonIdentifierClaimNames(t *testing.T) {
	names := []string{
		"https://example.com/roles",
		"urn:example:scope",
		"custom-claim",
		"custom.claim",
		"custom claim",
		"claim#1",
		"user@example.com",
		"日本語",
	}

	for _, name := range names {
		t.Run(name, func(t *testing.T) {
			claims := fmt.Sprintf(`{"sub":"alice","aud":"svc","%s":["admin"]}`, name)
			var jwt Jwt
			_, err := jwt.Unmarshal(compactJwt(`{"alg":"RS256","typ":"JWT","kid":"k1"}`, claims))
			require.NoError(t, err)

			out, err := json.Marshal(&jwt.Claims)
			require.NoError(t, err)

			var round map[string]json.RawMessage
			require.NoError(t, json.Unmarshal(out, &round))
			assert.JSONEq(t, `["admin"]`, string(round[name]),
				"claim %q must survive the marshal round-trip", name)
			assert.JSONEq(t, `"alice"`, string(round["sub"]))
			assert.JSONEq(t, `"svc"`, string(round["aud"]))
		})
	}
}

// "utomaticJwtClaims" became the field name "AutomaticJwtClaims", colliding with the
// embedded struct field and panicking with "duplicate field".
func TestJwtClaimsMarshalHandlesEmbeddedFieldNameCollisions(t *testing.T) {
	for _, name := range []string{"utomaticJwtClaims", "ettableJwtClaims"} {
		t.Run(name, func(t *testing.T) {
			claims := fmt.Sprintf(`{"sub":"alice","%s":["admin"]}`, name)
			var jwt Jwt
			_, err := jwt.Unmarshal(compactJwt(`{"alg":"RS256","typ":"JWT"}`, claims))
			require.NoError(t, err)

			out, err := json.Marshal(&jwt.Claims)
			require.NoError(t, err)

			var round map[string]json.RawMessage
			require.NoError(t, json.Unmarshal(out, &round))
			assert.JSONEq(t, `["admin"]`, string(round[name]))
		})
	}
}

// Reserved claim names must still be rejected when supplied as untyped claims.
func TestJwtClaimsMarshalStillRejectsReservedClaimNames(t *testing.T) {
	claims := JwtClaims{
		UntypedClaims: map[string]json.RawMessage{
			"iss": json.RawMessage(`"attacker"`),
		},
	}
	_, err := json.Marshal(&claims)
	assert.ErrorIs(t, err, ErrJwkReservedClaimName)
}

// RFC 7515 §4.1.11 requires a JWS to be rejected when it lists critical extension
// header parameters the recipient does not understand. gose implements no extensions,
// so any non-empty "crit" must be fatal. The header was parsed into JwsHeader.Crit and
// then read by nothing.
func TestJwtVerifyRejectsCritHeader(t *testing.T) {
	crits := [][]string{
		{"b64"},
		{"must-revoke-check"},
		{"urn:example:unsupported-extension"},
		{"b64", "cnf"},
	}

	for _, crit := range crits {
		t.Run(strings.Join(crit, ","), func(t *testing.T) {
			header, err := json.Marshal(map[string]any{
				"alg": "RS256", "typ": "JWT", "kid": "k1", "crit": crit,
			})
			require.NoError(t, err)

			var jwt Jwt
			_, err = jwt.Unmarshal(compactJwt(string(header), `{"sub":"alice"}`))
			assert.ErrorIs(t, err, ErrCritHeaderNotSupported)
		})
	}
}

// A token with no "crit", or an empty one, is unaffected.
func TestJwtVerifyAcceptsAbsentOrEmptyCrit(t *testing.T) {
	for name, header := range map[string]string{
		"absent": `{"alg":"RS256","typ":"JWT","kid":"k1"}`,
		"empty":  `{"alg":"RS256","typ":"JWT","kid":"k1","crit":[]}`,
	} {
		t.Run(name, func(t *testing.T) {
			var jwt Jwt
			_, err := jwt.Unmarshal(compactJwt(header, `{"sub":"alice"}`))
			assert.NoError(t, err)
		})
	}
}

// jwkFields.CheckConsistency scanned key_ops pairwise, so validation cost grew with the
// square of the entry count and a sub-1MB JWKS body could pin a core for ~15s.
func TestCheckConsistencyBoundsKeyOps(t *testing.T) {
	ops := make([]string, maxKeyOps+1)
	for i := range ops {
		ops[i] = fmt.Sprintf("op%d", i)
	}
	encoded, err := json.Marshal(ops)
	require.NoError(t, err)

	doc := fmt.Sprintf(`{"kty":"oct","alg":"A256GCM","k":"AQ","key_ops":%s}`, encoded)
	_, err = UnmarshalJwk(strings.NewReader(doc))
	assert.ErrorIs(t, err, ErrTooManyKeyOps)
}

// Duplicate detection must survive the switch from the pairwise scan to a set.
func TestCheckConsistencyStillDetectsDuplicateKeyOps(t *testing.T) {
	doc := `{"kty":"oct","alg":"A256GCM","k":"AQ","key_ops":["sign","verify","sign"]}`
	_, err := UnmarshalJwk(strings.NewReader(doc))
	assert.ErrorIs(t, err, ErrDuplicateKeyOps)
}

// A realistic key_ops list must still be accepted.
func TestCheckConsistencyAcceptsDistinctKeyOps(t *testing.T) {
	doc := `{"kty":"oct","alg":"A256GCM","k":"AQ","key_ops":["encrypt","decrypt"]}`
	jwk, err := UnmarshalJwk(strings.NewReader(doc))
	require.NoError(t, err)
	assert.Len(t, jwk.Ops(), 2)
}
