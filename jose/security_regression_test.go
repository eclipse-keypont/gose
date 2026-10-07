// SPDX-FileCopyrightText: 2026 Thales Group and the gose Contributors
// SPDX-License-Identifier: MIT

package jose

import (
	"encoding/base64"
	"encoding/json"
	"errors"
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

// UnmarshalJwk read the whole reader with io.ReadAll before parsing, so a large or
// unbounded stream was materialised in full. The read is now capped at MaxJwksSize.
func TestUnmarshalJwkRejectsOversizedDocument(t *testing.T) {
	oversized := strings.NewReader(strings.Repeat("a", MaxJwksSize+1))
	_, err := UnmarshalJwk(oversized)
	assert.ErrorIs(t, err, ErrInputTooLarge)
}

// A document at the bound must still be parsed (and rejected for its content, not size).
func TestUnmarshalJwkAcceptsDocumentAtBound(t *testing.T) {
	// Pad a valid JWK with whitespace to exactly MaxJwksSize bytes.
	doc := `{"kty":"oct","alg":"A256GCM","k":"AQ"}`
	padded := doc + strings.Repeat(" ", MaxJwksSize-len(doc))
	require.Len(t, padded, MaxJwksSize)
	jwk, err := UnmarshalJwk(strings.NewReader(padded))
	require.NoError(t, err)
	assert.Equal(t, KtyOct, jwk.Kty())
}

// Jwks.UnmarshalJSON decoded the whole body before iterating its keys.
func TestJwksUnmarshalRejectsOversizedDocument(t *testing.T) {
	var jwks Jwks
	err := jwks.UnmarshalJSON([]byte(strings.Repeat("a", MaxJwksSize+1)))
	assert.ErrorIs(t, err, ErrInputTooLarge)
}

// The compact JWE parser split and base64-decoded every segment before any size check.
func TestJweCompactUnmarshalRejectsOversizedInput(t *testing.T) {
	var jwe JweRfc7516Compact
	err := jwe.Unmarshal(strings.Repeat("a", MaxCompactSize+1))
	assert.ErrorIs(t, err, ErrInputTooLarge)
}

// The legacy JWE parser had the same unbounded decode.
func TestJweLegacyUnmarshalRejectsOversizedInput(t *testing.T) {
	var jwe Jwe
	err := jwe.Unmarshal(strings.Repeat("a", MaxCompactSize+1))
	assert.ErrorIs(t, err, ErrInputTooLarge)
}

// The compact JWS parser had the same unbounded decode.
func TestJwsUnmarshalRejectsOversizedInput(t *testing.T) {
	var jws Jws
	_, err := jws.Unmarshal(strings.Repeat("a", MaxCompactSize+1))
	assert.ErrorIs(t, err, ErrInputTooLarge)
}

// unmarshalJSONBlob sized its buffer from the input length, so an oversized base64url
// member — an RSA modulus, a symmetric key, an x5c certificate — was decoded into a
// matching allocation. The check now runs before the allocation.
func TestUnmarshalJSONBlobRejectsOversizedMember(t *testing.T) {
	big := base64.RawURLEncoding.EncodeToString(make([]byte, MaxBlobSize+1))
	doc := fmt.Sprintf(`{"kty":"oct","alg":"A256GCM","k":"%s"}`, big)
	_, err := UnmarshalJwk(strings.NewReader(doc))
	assert.ErrorIs(t, err, ErrInputTooLarge)
}

// A member at the bound must still decode, so the guard is not off by one.
func TestUnmarshalJSONBlobAcceptsMemberAtBound(t *testing.T) {
	atBound := base64.RawURLEncoding.EncodeToString(make([]byte, MaxBlobSize))
	doc := fmt.Sprintf(`{"kty":"oct","alg":"A256GCM","k":"%s"}`, atBound)
	jwk, err := UnmarshalJwk(strings.NewReader(doc))
	require.NoError(t, err)
	assert.Len(t, jwk.(*OctSecretKey).K.Bytes(), MaxBlobSize)
}

// compactJwe assembles a compact JWE from a raw protected-header JSON object and
// placeholder segments.
func compactJwe(header string) string {
	b64 := base64.RawURLEncoding.EncodeToString
	return strings.Join([]string{
		b64([]byte(header)), "", b64([]byte("iv")), b64([]byte("ct")), b64([]byte("tag")),
	}, ".")
}

// M-G20: JweRfc7516Compact.Unmarshal parsed the protected header and handed it to
// consumers without checking that "alg" and "enc" were present and supported. RFC 7516
// §4.1.1/§4.1.2 require both, and a header naming an algorithm gose cannot perform must
// not be acted on.
func TestJweCompactUnmarshalRejectsUnsupportedHeader(t *testing.T) {
	cases := map[string]string{
		"missing alg":       `{"enc":"A256GCM"}`,
		"missing enc":       `{"alg":"dir"}`,
		"unknown alg":       `{"alg":"none","enc":"A256GCM"}`,
		"unknown enc":       `{"alg":"dir","enc":"A999GCM"}`,
		"empty header":      `{}`,
		"unsupported combo": `{"alg":"HS256","enc":"A256GCM"}`,
	}
	for name, header := range cases {
		t.Run(name, func(t *testing.T) {
			var jwe JweRfc7516Compact
			err := jwe.Unmarshal(compactJwe(header))
			require.Error(t, err)
			assert.True(t,
				errors.Is(err, ErrInvalidAlgorithm) || errors.Is(err, ErrInvalidEncryption),
				"expected an algorithm/encryption error, got %v", err)
		})
	}
}

// A header naming a supported alg/enc pair must still parse.
func TestJweCompactUnmarshalAcceptsSupportedHeader(t *testing.T) {
	for _, header := range []string{
		`{"alg":"dir","enc":"A256GCM"}`,
		`{"alg":"RSA-OAEP","enc":"A256GCM"}`,
		`{"alg":"RSA-OAEP-256","enc":"A128GCM"}`,
		`{"alg":"A256CBC","enc":"A256CBC"}`,
	} {
		t.Run(header, func(t *testing.T) {
			var jwe JweRfc7516Compact
			require.NoError(t, jwe.Unmarshal(compactJwe(header)))
		})
	}
}

// M-G10: a JWK whose "kty" does not match the type it is being decoded as must be
// rejected. The UnmarshalJSON methods used to overwrite the ErrUnexpectedKeyType with
// the result of CheckConsistency, so a wrong-typed document could be accepted.
func TestJwkUnmarshalRejectsWrongKeyType(t *testing.T) {
	cases := map[string]struct {
		doc  string
		into func() any
	}{
		"oct as RSA": {
			doc:  `{"kty":"oct","k":"AQ"}`,
			into: func() any { return &PublicRsaKey{} },
		},
		"RSA as EC": {
			doc:  `{"kty":"RSA","n":"AQ","e":"AQAB"}`,
			into: func() any { return &PublicEcKey{} },
		},
		"EC as oct": {
			doc:  `{"kty":"EC","crv":"P-256","x":"AQ","y":"AQ"}`,
			into: func() any { return &OctSecretKey{} },
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			err := json.Unmarshal([]byte(tc.doc), tc.into())
			assert.ErrorIs(t, err, ErrUnexpectedKeyType)
		})
	}
}
