// SPDX-FileCopyrightText: 2026 Thales Group and the gose Contributors
// SPDX-License-Identifier: MIT

package jose

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

// JwsHeader header for JWS
type JwsHeader struct {
	Alg Alg    `json:"alg"`
	Jku string `json:"jku,omitempty"`
	//jwkFields []jwkFields `json:"jwk,omitempty"`  TODO finish this
	Kid    string   `json:"kid,omitempty"`
	X5U    string   `json:"x5u,omitempty"`
	X5C    [][]byte `json:"x5c,omitempty"`
	X5T    *Blob    `json:"x5t,omitempty"`
	X5T256 *Blob    `json:"x5t#S256,omitempty"`
	Typ    JwsType  `json:"typ,omitempty"`
	Cty    JwsType  `json:"cty,omitempty"`
	Crit   []string `json:"crit,omitempty"`
}

// Audiences holds audience members
type Audiences struct {
	Aud []string
}

// UnmarshalJSON byte slice to audience members or error. The claim is either a string or an
// array of strings (RFC 7519 §4.1.3). An array is read member by member and rejected with
// ErrInputTooLarge once it exceeds MaxAudiences, so an oversized one is not decoded in full.
func (audiences *Audiences) UnmarshalJSON(src []byte) error {
	dec := json.NewDecoder(bytes.NewReader(src))
	tok, err := dec.Token()
	if err != nil {
		return ErrJSONFormat
	}
	switch t := tok.(type) {
	case string:
		audiences.Aud = append(audiences.Aud, t)
		return nil
	case json.Delim:
		if t != '[' {
			return ErrJSONFormat
		}
		for dec.More() {
			if len(audiences.Aud) >= MaxAudiences {
				return ErrInputTooLarge
			}
			if tok, err = dec.Token(); err != nil {
				return ErrJSONFormat
			}
			str, ok := tok.(string)
			if !ok {
				return ErrJSONFormat
			}
			audiences.Aud = append(audiences.Aud, str)
		}
		return nil
	default:
		return ErrJSONFormat
	}
}

// MarshalJSON audience to byte slice or error
func (audiences *Audiences) MarshalJSON() (dst []byte, err error) {
	switch len(audiences.Aud) {
	case 1:
		// Special case.
		return json.Marshal(audiences.Aud[0])
	default:
		return json.Marshal(audiences.Aud)
	}
}

// Jws jave web signature
type Jws struct {
	Header    *JwsHeader
	Payload   interface{}
	Signature []byte
}

// MarshalBody marshaled representation of the JWT Header and Claims.
func (jws *Jws) MarshalBody() (body string, err error) {
	if jws.Header.Typ != JwtType {
		/* Not a JWT. */
		err = ErrJwtFormat
		return
	}
	if jws.Header.Cty != "" && jws.Header.Cty != JwtType {
		err = ErrJwtFormat
		return
	}
	var header []byte
	if header, err = json.Marshal(&jws.Header); err != nil {
		return
	}
	var claims []byte
	if claims, err = json.Marshal(&jws.Payload); err != nil {
		return
	}
	body = fmt.Sprintf("%s.%s",
		base64.RawURLEncoding.EncodeToString(header),
		base64.RawURLEncoding.EncodeToString(claims))
	return
}

// Body return either the original JWS payload or alternatively one generated.
func (jws *Jws) Body() (body string, err error) {
	body, err = jws.MarshalBody()
	return
}

// Unmarshal to body string, or error
func (jws *Jws) Unmarshal(src string) (body string, err error) {
	// Bound before splitting/decoding: the input is attacker-supplied and every part
	// below is decoded into a fresh allocation.
	if len(src) > MaxCompactSize {
		err = ErrInputTooLarge
		return
	}
	/* Compact JWS encoding. */
	parts := strings.SplitN(src, ".", 3)
	if len(parts) != 3 {
		err = ErrJwtFormat
		return
	}
	if err = unmarshalURLBase64(parts[0], &(jws.Header)); err != nil {
		return
	}
	if err = unmarshalURLBase64(parts[1], &(jws.Payload)); err != nil {
		return
	}

	// Decode the signature segment strictly. The header and payload are covered by the
	// signature over the raw parts[0].parts[1] octets, so tampering there is caught by
	// verification; the signature segment itself is not, so a non-canonical encoding of
	// it (non-zero trailing bits, or a CR/LF the base64 decoder would skip) would yield a
	// second token string carrying the same signature bytes. Reject any such encoding so a
	// verified token has one canonical serialisation.
	if jws.Signature, err = strictCompactB64(parts[2]); err != nil {
		err = ErrJwtFormat
		return
	}
	body = strings.Join(parts[:2], ".")
	return
}

// strictCompactB64 decodes a raw-base64url segment and rejects any encoding that is not
// the canonical form of the bytes it yields: re-encoding the result must reproduce the
// input exactly. This catches non-zero trailing bits and CR/LF that encoding/base64 would
// otherwise accept, either of which lets two distinct strings decode to the same bytes.
func strictCompactB64(s string) ([]byte, error) {
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil, err
	}
	if base64.RawURLEncoding.EncodeToString(b) != s {
		return nil, ErrJwtFormat
	}
	return b, nil
}

// MarshalJws body and signature to a string
func MarshalJws(body string, signature []byte) string {
	return fmt.Sprintf("%s.%s", body, base64.RawURLEncoding.EncodeToString(signature))
}
