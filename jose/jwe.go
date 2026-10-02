// SPDX-FileCopyrightText: 2026 Thales Group and the gose Contributors
// SPDX-License-Identifier: MIT

package jose

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

// JweCustomHeaderFields custom JWE defined fields.
type JweCustomHeaderFields struct {
	// Other AAD for transporting AAD around with the JWE...
	OtherAad *Blob `json:"_thales_aad,omitempty"`
}

// JweHeader JWE header fields.
//
// Deprecated: Use JweProtectedHeader instead.
type JweHeader struct {
	JwsHeader
	JweCustomHeaderFields
	Enc Enc `json:"enc"`
	Zip Zip `json:"zip,omitempty"`
}

// JwePerRecipientUnprotectedHeader is a JSON object that contains Header Parameters that apply to a single
//
//	recipient of the JWE.  These Header Parameter values are not
//	integrity protected.  This can only be present when using the JWE
//	JSON Serialization.
type JwePerRecipientUnprotectedHeader struct {
	PlaintextLength int `json:"plaintextLength"`
}

// JweSharedUnprotectedHeader is a JSON object that contains the Header Parameters that apply to all
//
//	recipients of the JWE that are not integrity protected.  This can
//	only be present when using the JWE JSON Serialization.
type JweSharedUnprotectedHeader struct{}

// JweProtectedHeader is a JSON object that contains the Header Parameters that are integrity
//
//	protected by the authenticated encryption operation.  These
//	parameters apply to all recipients of the JWE.  For the JWE
//	Compact Serialization, this comprises the entire JOSE Header.  For
//	the JWE JSON Serialization, this is one component of the JOSE
//	Header.
type JweProtectedHeader struct {
	JwsHeader
	JweCustomHeaderFields
	Enc Enc `json:"enc"`
	Zip Zip `json:"zip,omitempty"`
}

// HeaderRfc7516 is the JOSE Header for a JWE, the union of the members of :
//
//	o  JWE Protected Header
//	o  JWE Shared Unprotected Header
//	o  JWE Per-Recipient Unprotected Header
type HeaderRfc7516 struct {
	JweProtectedHeader
	JweSharedUnprotectedHeader
	JwePerRecipientUnprotectedHeader
}

// JweRfc7516Compact represents a JWE using the Compact Serialization as defined by https://tools.ietf.org/html/rfc7516.
type JweRfc7516Compact struct {
	ProtectedHeader      JweProtectedHeader
	EncryptedKey         []byte
	InitializationVector []byte
	Ciphertext           []byte
	AuthenticationTag    []byte
}

// JweRfc7516 represents a JWE using the JSON Serialization as defined by https://tools.ietf.org/html/rfc7516.
type JweRfc7516 struct {
	Header               HeaderRfc7516
	EncryptedKey         []byte
	InitializationVector []byte
	Ciphertext           []byte
	AuthenticationTag    []byte
	AAD                  []byte
}

// Jwe representation of a JWE.
//
// Deprecated: Does not conform to RFC 7516. Use JweRfc7516Compact instead.
type Jwe struct {
	Header           JweHeader
	MarshalledHeader []byte
	EncryptedKey     []byte
	Iv               []byte
	Ciphertext       []byte
	Tag              []byte
	Plaintext        []byte
}

// MarshalHeader marshal JWE header. Note this is not guaranteed to result in the same marshaled representation across
// invocations.
func (jwe *Jwe) MarshalHeader() (err error) {
	var marshalledHeader []byte
	if marshalledHeader, err = jwe.Header.MarshalHeader(); err != nil {
		return
	}
	jwe.MarshalledHeader = marshalledHeader
	return
}

// MarshalHeader marshals the JWE header to its base64url-encoded JSON representation.
func (jweHeader *JweHeader) MarshalHeader() (marshalledHeader []byte, err error) {
	var headerBytes []byte
	if headerBytes, err = json.Marshal(jweHeader); err != nil {
		return nil, err
	}
	return []byte(base64.RawURLEncoding.EncodeToString(headerBytes)), nil
}

// MarshalProtectedHeader marshals the JWE protected header to its base64url-encoded JSON representation.
func (jweProtectedHeader *JweProtectedHeader) MarshalProtectedHeader() (marshalledHeader []byte, err error) {
	var headerBytes []byte
	if headerBytes, err = json.Marshal(jweProtectedHeader); err != nil {
		return nil, err
	}
	return []byte(base64.RawURLEncoding.EncodeToString(headerBytes)), nil
}

func concatByteArrays(slices [][]byte) []byte {
	var tmp []byte
	for _, s := range slices {
		tmp = append(tmp, s...)
	}
	return tmp
}

// MarshallHeader marshals the union of the protected, shared unprotected, and per-recipient unprotected headers.
func (jweHeader *HeaderRfc7516) MarshallHeader() (marshalledHeader []byte, err error) {
	var protectedHeaderBytes []byte
	var sharedUnprotectedHeaderBytes []byte
	var perRecipientUnprotectedHeaderBytes []byte
	if protectedHeaderBytes, err = jweHeader.MarshalProtectedHeader(); err != nil {
		return nil, err
	}
	if sharedUnprotectedHeaderBytes, err = json.Marshal(jweHeader.JweSharedUnprotectedHeader); err != nil {
		return nil, err
	}
	if perRecipientUnprotectedHeaderBytes, err = json.Marshal(jweHeader.JwePerRecipientUnprotectedHeader); err != nil {
		return nil, err
	}
	encodedHeaders := [][]byte{
		[]byte(base64.RawURLEncoding.EncodeToString(protectedHeaderBytes)),
		[]byte(base64.RawURLEncoding.EncodeToString(sharedUnprotectedHeaderBytes)),
		[]byte(base64.RawURLEncoding.EncodeToString(perRecipientUnprotectedHeaderBytes)),
	}
	return concatByteArrays(encodedHeaders), nil
}

// Unmarshal to body string, or error.
//
// Deprecated: Does not conform to RFC 7516. Use JweRfc7516Compact.Unmarshal instead.
func (jwe *Jwe) Unmarshal(src string) (err error) {
	/* Compact JWS encoding. */
	parts := strings.SplitN(src, ".", 5)
	if len(parts) != 5 {
		err = ErrJweFormat
		return
	}
	if jwe.MarshalledHeader, err = base64.RawURLEncoding.DecodeString(parts[0]); err != nil {
		return
	}
	if err = json.Unmarshal(jwe.MarshalledHeader, &jwe.Header); err != nil {
		return
	}
	jwe.MarshalledHeader = []byte(parts[0])
	// JWE Encrypted key can be a zero length key in scenarios such as direct encoding.
	if len(parts[1]) > 0 {
		if jwe.EncryptedKey, err = base64.RawURLEncoding.DecodeString(parts[1]); err != nil {
			return
		}
	}
	if jwe.Iv, err = base64.RawURLEncoding.DecodeString(parts[2]); err != nil {
		return
	}
	if jwe.Ciphertext, err = base64.RawURLEncoding.DecodeString(parts[3]); err != nil {
		return
	}
	if jwe.Tag, err = base64.RawURLEncoding.DecodeString(parts[4]); err != nil {
		return
	}
	return
}

// Unmarshal parses a compact-serialized JWE string into its constituent parts.
func (jwe *JweRfc7516Compact) Unmarshal(src string) (err error) {
	// Compact JWE are divided in 5 parts :
	//   o  Protected Header
	//   o  Encrypted Key
	//   o  Initialization Vector
	//   o  Ciphertext
	//   o  Authentication Tag
	parts := strings.SplitN(src, ".", 5)
	if len(parts) != 5 {
		err = ErrJweFormat
		return
	}
	// Unmarshall JWE Protected Header
	var marshalledHeader []byte
	if marshalledHeader, err = base64.RawURLEncoding.DecodeString(parts[0]); err != nil {
		return
	}
	if err = json.Unmarshal(marshalledHeader, &jwe.ProtectedHeader); err != nil {
		return
	}
	// JWE Encrypted Key
	//  can be a zero length key in scenarios such as direct encoding.
	if len(parts[1]) > 0 {
		if jwe.EncryptedKey, err = base64.RawURLEncoding.DecodeString(parts[1]); err != nil {
			return
		}
	}
	// JWE Initialization Vector
	if jwe.InitializationVector, err = base64.RawURLEncoding.DecodeString(parts[2]); err != nil {
		return
	}
	// JWE Ciphertext
	if jwe.Ciphertext, err = base64.RawURLEncoding.DecodeString(parts[3]); err != nil {
		return
	}
	// Authentication Tag
	if jwe.AuthenticationTag, err = base64.RawURLEncoding.DecodeString(parts[4]); err != nil {
		return
	}
	return
}

// Marshal a JWE to it's compact representation.
func (jwe *Jwe) Marshal() string {
	stringz := []string{
		string(jwe.MarshalledHeader),
		base64.RawURLEncoding.EncodeToString(jwe.EncryptedKey),
		base64.RawURLEncoding.EncodeToString(jwe.Iv),
		base64.RawURLEncoding.EncodeToString(jwe.Ciphertext),
		base64.RawURLEncoding.EncodeToString(jwe.Tag),
	}
	return strings.Join(stringz, ".")
}

// Marshal a JWE to it's compact representation.
//
//	Follow these steps:
//	 1. encode BASE64URL(UTF8(JWE ProtectedHeader))
//	 2. Encode BASE64URL(JWE Encrypted Key)
//	 3. Encode BASE64URL(JWE Initialization Vector)
//	 4. Create AAD, which is already ASCII(BASE64URL(UTF8(JWE Protected Header))).
//	 5. encode AL as an octet string for the unsigned int. Example : [0, 0, 0, 0, 0, 0, 1, 152].
//	 6. Encode BASE64URL(JWE Ciphertext).
//	 7. Encode BASE64URL(JWE Authentication Tag).
//
// TODO add the aad and the al
func (jwe *JweRfc7516Compact) Marshal() (marshalledJwe string, err error) {
	var marshalledHeader []byte
	if marshalledHeader, err = jwe.ProtectedHeader.MarshalProtectedHeader(); err != nil {
		return "", fmt.Errorf("error marshalling the JWE header: %w", err)
	}
	stringz := []string{
		string(marshalledHeader),
		base64.RawURLEncoding.EncodeToString(jwe.EncryptedKey),
		base64.RawURLEncoding.EncodeToString(jwe.InitializationVector),
		base64.RawURLEncoding.EncodeToString(jwe.Ciphertext),
		base64.RawURLEncoding.EncodeToString(jwe.AuthenticationTag),
	}
	return strings.Join(stringz, "."), nil
}
