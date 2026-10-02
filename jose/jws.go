// SPDX-FileCopyrightText: 2026 Thales Group and the gose Contributors
// SPDX-License-Identifier: MIT

package jose

import (
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

// UnmarshalJSON byte slice to audience members or error
func (audiences *Audiences) UnmarshalJSON(src []byte) (err error) {
	var toUnmarshal interface{}
	if err = json.Unmarshal(src, &toUnmarshal); err != nil {
		return
	}
	switch t := toUnmarshal.(type) {
	case string:
		audiences.Aud = append(audiences.Aud, t)
	case []interface{}:
		for _, item := range t {
			str, ok := item.(string)
			if !ok {
				err = ErrJSONFormat
				return
			}
			audiences.Aud = append(audiences.Aud, str)
		}
	default:
		err = ErrJSONFormat
	}
	return
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

	if jws.Signature, err = base64.RawURLEncoding.DecodeString(parts[2]); err != nil {
		err = ErrJwtFormat
		return
	}
	body = strings.Join(parts[:2], ".")
	return
}

// MarshalJws body and signature to a string
func MarshalJws(body string, signature []byte) string {
	return fmt.Sprintf("%s.%s", body, base64.RawURLEncoding.EncodeToString(signature))
}
