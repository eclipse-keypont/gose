// SPDX-FileCopyrightText: 2026 Thales Group and the gose Contributors
// SPDX-License-Identifier: MIT

package jose

import (
	"bytes"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"reflect"
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestJsonUnmarshal_LastKeyWins(t *testing.T) {
	// The various JOSE specifications state JSOn objects with duplicate entries should either be rejected or the last
	// entry wins. As all our objects are typed we should hit this issue during encoding but we may in decoding. This test
	// just clarifies the go runtime is doing what we want which is to take the last entry.
	type TestType struct {
		Field string
	}
	testCases := []struct {
		input    string
		expected TestType
	}{
		{
			input: `{"Field":"first","Field":"last"}`,
			expected: TestType{
				Field: "last",
			},
		},
		{
			input: `{"Field":"1","Field":"2","Field":"3"}`,
			expected: TestType{
				Field: "3",
			},
		},
		{
			input: `{"Field":"one","Field":"more","Field":"test"}`,
			expected: TestType{
				Field: "test",
			},
		},
	}

	// Act//Assert
	for i, test := range testCases {
		t.Run(fmt.Sprintf("%d", i+1),
			func(t *testing.T) {
				var item TestType
				err := json.Unmarshal([]byte(test.input), &item)
				require.NoError(t, err)
				assert.Equal(t, test.expected.Field, item.Field)
			})
	}
}

func TestPublicRSA_UnmarshalJSON(t *testing.T) {
	// Setup
	const input = `
{
	"kty": "RSA",
	"n": "BBBB",
	"e": "AQAB",
	"kid": "1",
	"x5c": ["MIID9jCCAt6gAwIBAgIJAJjAfywQgInaMA0GCSqGSIb3DQEBCwUAMIGOMQswCQYDVQQGEwJBVTETMBEGA1UECAwKU29tZS1TdGF0ZTESMBAGA1UEBwwJc29tZS1jaXR5MRMwEQYDVQQKDAphY21lIGNvcnAuMQ0wCwYDVQQLDAR0ZXN0MREwDwYDVQQDDAhhY21lLmNvbTEfMB0GCSqGSIb3DQEJARYQbm93aGVyZUBhY21lLmNvbTAgFw0xODEyMTAxMjMxNTdaGA8yNTY2MDcxMDEyMzE1N1owgY4xCzAJBgNVBAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMRIwEAYDVQQHDAlzb21lLWNpdHkxEzARBgNVBAoMCmFjbWUgY29ycC4xDTALBgNVBAsMBHRlc3QxETAPBgNVBAMMCGFjbWUuY29tMR8wHQYJKoZIhvcNAQkBFhBub3doZXJlQGFjbWUuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzMi/g4y3Zgr4z5azcA3wgDfvqFBYYX9GQldp2Po8127I26Ln6fugWPN3vGPD++cM+eZbeTfbqomw3ZPmdmgPDwGx5ODoa9a32Ar9MdTQQxltvlSWvyF2c92ZZ9DUBedVNHArTJmbPRofBpqHuBDxn1NsY9neA75lgxFsatbzEHI2FKva3TSwREZlOEuSkYQVsfZAT3c3TnSMVRs0jY8qQijBs59inH0PjlGeiNnZNcpVC7jYrP4PjJFnBgSC4gz2aYy0cLNcLdPsckJM/84eepexQ97+SBERm9eMXTeoCxMUflEfXEa0DXn4WdGBMM7XT6hF7xqnHs62M0OeOYJMYwIDAQABo1MwUTAdBgNVHQ4EFgQUCiyj1kOqmpWm1WPl0pjihQskpXIwHwYDVR0jBBgwFoAUCiyj1kOqmpWm1WPl0pjihQskpXIwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAsGVlC6nFydUA3NEoA2hqmZXVxXvPLHTTTh1ZSYUf9WhMNEPUUjrwx/KCY4UBEoVqF5LfH872Fjf+nQSorpnJAC0kPM2VoAp2n74Dj5IgDz6OUw0b4cSeVEnNm6gyf088VsiVyunbG5peiZ4rexBJ4dcRzWMOkUvtXZmTYkv/WM5WlmSTPLFdbaSr4Pkzk1bjGpP5Qc4k24tIFqKbh3AxZ04VkRPb39DHo/KATJPG1Or/c1TxsyfOKV8OrEpl0spyLeUDkQ6ZA7KDym8y6IUCGNff58zsdlgEpfa7PtcNl/AinkWC519MhkyWhQU15AnkXSQ42bAnoDuzM+xBuasDyw=="],
	"x5t": "PCq4Z1N-ranPT0wQq1G5ezVk7b4"
}
`
	// Act
	var rsa PublicRsaKey
	err := json.Unmarshal([]byte(input), &rsa)

	// Assert
	assert.NoError(t, err)
	assert.Equal(t, KtyRSA, rsa.Kty())
	assert.Equal(t, int64(65537), rsa.E.Int().Int64())
	assert.Equal(t, int64(266305), rsa.N.Int().Int64())
	assert.Equal(t, "1", rsa.Kid())
	assert.Equal(t, 1, len(rsa.X5C()))
}

func TestPublicRSA_MarshalJSON(t *testing.T) {
	// Setup
	certBytes, err := base64.StdEncoding.DecodeString("MIID9jCCAt6gAwIBAgIJAJjAfywQgInaMA0GCSqGSIb3DQEBCwUAMIGOMQswCQYDVQQGEwJBVTETMBEGA1UECAwKU29tZS1TdGF0ZTESMBAGA1UEBwwJc29tZS1jaXR5MRMwEQYDVQQKDAphY21lIGNvcnAuMQ0wCwYDVQQLDAR0ZXN0MREwDwYDVQQDDAhhY21lLmNvbTEfMB0GCSqGSIb3DQEJARYQbm93aGVyZUBhY21lLmNvbTAgFw0xODEyMTAxMjMxNTdaGA8yNTY2MDcxMDEyMzE1N1owgY4xCzAJBgNVBAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMRIwEAYDVQQHDAlzb21lLWNpdHkxEzARBgNVBAoMCmFjbWUgY29ycC4xDTALBgNVBAsMBHRlc3QxETAPBgNVBAMMCGFjbWUuY29tMR8wHQYJKoZIhvcNAQkBFhBub3doZXJlQGFjbWUuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzMi/g4y3Zgr4z5azcA3wgDfvqFBYYX9GQldp2Po8127I26Ln6fugWPN3vGPD++cM+eZbeTfbqomw3ZPmdmgPDwGx5ODoa9a32Ar9MdTQQxltvlSWvyF2c92ZZ9DUBedVNHArTJmbPRofBpqHuBDxn1NsY9neA75lgxFsatbzEHI2FKva3TSwREZlOEuSkYQVsfZAT3c3TnSMVRs0jY8qQijBs59inH0PjlGeiNnZNcpVC7jYrP4PjJFnBgSC4gz2aYy0cLNcLdPsckJM/84eepexQ97+SBERm9eMXTeoCxMUflEfXEa0DXn4WdGBMM7XT6hF7xqnHs62M0OeOYJMYwIDAQABo1MwUTAdBgNVHQ4EFgQUCiyj1kOqmpWm1WPl0pjihQskpXIwHwYDVR0jBBgwFoAUCiyj1kOqmpWm1WPl0pjihQskpXIwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAsGVlC6nFydUA3NEoA2hqmZXVxXvPLHTTTh1ZSYUf9WhMNEPUUjrwx/KCY4UBEoVqF5LfH872Fjf+nQSorpnJAC0kPM2VoAp2n74Dj5IgDz6OUw0b4cSeVEnNm6gyf088VsiVyunbG5peiZ4rexBJ4dcRzWMOkUvtXZmTYkv/WM5WlmSTPLFdbaSr4Pkzk1bjGpP5Qc4k24tIFqKbh3AxZ04VkRPb39DHo/KATJPG1Or/c1TxsyfOKV8OrEpl0spyLeUDkQ6ZA7KDym8y6IUCGNff58zsdlgEpfa7PtcNl/AinkWC519MhkyWhQU15AnkXSQ42bAnoDuzM+xBuasDyw==")
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(certBytes)
	require.NoError(t, err)
	digestBytes, err := base64.RawURLEncoding.DecodeString("PCq4Z1N-ranPT0wQq1G5ezVk7b4")
	require.NoError(t, err)
	var rsa PublicRsaKey
	rsa.SetKid("1")
	rsa.SetX5C([]*x509.Certificate{cert})
	rsa.SetX5T(&Fingerprint{digest: digestBytes})
	rsa.N.SetBytes([]byte{0, 1, 2, 3, 4})
	rsa.E.SetBytes([]byte{1, 0, 1})

	// Act
	output, err := json.Marshal(&rsa)

	// Assert
	assert.NoError(t, err)
	assert.Regexp(t, regexp.MustCompile(`"kty":\s*"RSA"`), string(output))
	assert.Regexp(t, regexp.MustCompile(`"kid":\s*"1"`), string(output))
	assert.Regexp(t, regexp.MustCompile(`"n":\s*"AQIDBA"`), string(output))
	assert.Regexp(t, regexp.MustCompile(`"e":\s*"AQAB"`), string(output))
	assert.Regexp(t, regexp.MustCompile(`"x5t":\s*"PCq4Z1N-ranPT0wQq1G5ezVk7b4"`), string(output))
}

func TestPrivateRSA_UnmarshalJSON(t *testing.T) {
	// Setup
	const input = `
{
	"kty": "RSA",
	"n": "BBBB",
	"e": "AQAB",
	"d": "BBBB",
	"p": "BBBB",
	"q": "BBBB",
	"dp": "BBBB",
	"dq": "BBBB",
	"qi": "BBBB",
	"kid": "1"
}`
	// Act
	var rsa PrivateRsaKey
	err := json.Unmarshal([]byte(input), &rsa)

	// Assert
	assert.NoError(t, err)
	assert.Equal(t, KtyRSA, rsa.Kty())
	assert.Equal(t, int64(65537), rsa.E.Int().Int64())
	assert.Equal(t, "1", rsa.Kid())
	assert.Equal(t, int64(266305), rsa.N.Int().Int64())
	assert.Equal(t, int64(266305), rsa.D.Int().Int64())
	assert.Equal(t, int64(266305), rsa.P.Int().Int64())
	assert.Equal(t, int64(266305), rsa.Q.Int().Int64())
	assert.Equal(t, int64(266305), rsa.Dp.Int().Int64())
	assert.Equal(t, int64(266305), rsa.Dq.Int().Int64())
	assert.Equal(t, int64(266305), rsa.Qi.Int().Int64())
}

func TestPrivateRSA_MarshalJSON(t *testing.T) {
	// Setup
	var rsa PrivateRsaKey
	rsa.SetKid("1")
	rsa.N.SetBytes([]byte{0, 1, 2, 3, 4})
	rsa.D.SetBytes([]byte{0, 1, 2, 3, 4})
	rsa.P.SetBytes([]byte{0, 1, 2, 3, 4})
	rsa.Q.SetBytes([]byte{0, 1, 2, 3, 4})
	rsa.Dp.SetBytes([]byte{0, 1, 2, 3, 4})
	rsa.Dq.SetBytes([]byte{0, 1, 2, 3, 4})
	rsa.Qi.SetBytes([]byte{0, 1, 2, 3, 4})
	rsa.E.SetBytes([]byte{1, 0, 1})

	// Act
	output, err := json.Marshal(&rsa)

	// Assert
	assert.NoError(t, err)
	assert.Regexp(t, regexp.MustCompile(`"kty":\s*"RSA"`), string(output))
	assert.Regexp(t, regexp.MustCompile(`"kid":\s*"1"`), string(output))
	assert.Regexp(t, regexp.MustCompile(`"n":\s*"AQIDBA"`), string(output))
	assert.Regexp(t, regexp.MustCompile(`"d":\s*"AQIDBA"`), string(output))
	assert.Regexp(t, regexp.MustCompile(`"p":\s*"AQIDBA"`), string(output))
	assert.Regexp(t, regexp.MustCompile(`"q":\s*"AQIDBA"`), string(output))
	assert.Regexp(t, regexp.MustCompile(`"dp":\s*"AQIDBA"`), string(output))
	assert.Regexp(t, regexp.MustCompile(`"dq":\s*"AQIDBA"`), string(output))
	assert.Regexp(t, regexp.MustCompile(`"qi":\s*"AQIDBA"`), string(output))
	assert.Regexp(t, regexp.MustCompile(`"e":\s*"AQAB"`), string(output))
}

func TestPublicEC_UnmarshalJSON(t *testing.T) {
	// Setup
	const input = `
{
	"kty": "EC",
	"crv": "P-256",
	"x": "BBBB",
	"y": "AQAB",
	"kid": "1"
}
`
	// Act
	var ec PublicEcKey
	err := json.Unmarshal([]byte(input), &ec)

	// Assert
	assert.NoError(t, err)
	assert.Equal(t, KtyEC, ec.Kty())
	assert.Equal(t, CrvP256, ec.Crv)
	assert.Equal(t, int64(266305), ec.X.Int().Int64())
	assert.Equal(t, int64(65537), ec.Y.Int().Int64())
	assert.Equal(t, "1", ec.Kid())
}

func TestPublicEC_MarshalJSON(t *testing.T) {
	// Setup
	var ec PublicEcKey
	ec.SetKid("1")
	ec.Crv = CrvP256
	ec.X.Int().SetBytes([]byte{1, 0, 1})
	ec.Y.Int().SetBytes([]byte{1, 0, 1})

	// Act
	dst, err := json.Marshal(&ec)

	// Assert
	assert.NoError(t, err)
	assert.Regexp(t, regexp.MustCompile(`"kty":\s*"EC"`), string(dst))
	assert.Regexp(t, regexp.MustCompile(`"kid":\s*"1"`), string(dst))
	assert.Regexp(t, regexp.MustCompile(`"x":\s*"AQAB"`), string(dst))
	assert.Regexp(t, regexp.MustCompile(`"y":\s*"AQAB"`), string(dst))
}

func TestPrivateEC_UnmarshalJSON(t *testing.T) {
	// Setup
	const input = `
{
	"kty": "EC",
	"crv": "P-256",
	"d": "CCCC",
	"x": "BBBB",
	"y": "AQAB",
	"kid": "1"
}
`
	// Act
	var ec PrivateEcKey
	err := json.Unmarshal([]byte(input), &ec)

	// Assert
	assert.NoError(t, err)
	assert.Equal(t, KtyEC, ec.Kty())
	assert.Equal(t, CrvP256, ec.Crv)
	assert.Equal(t, int64(532610), ec.D.Int().Int64())
	assert.Equal(t, int64(266305), ec.X.Int().Int64())
	assert.Equal(t, int64(65537), ec.Y.Int().Int64())
	assert.Equal(t, "1", ec.Kid())
}

func TestPrivateEC_MarshalJSON(t *testing.T) {
	// Setup
	var ec PrivateEcKey
	ec.SetKid("1")
	ec.Crv = CrvP256
	ec.X.Int().SetBytes([]byte{1, 0, 1})
	ec.Y.Int().SetBytes([]byte{1, 0, 1})
	ec.D.Int().SetBytes([]byte{1, 0, 1})

	// Act
	dst, err := json.Marshal(&ec)

	// Assert
	assert.NoError(t, err)
	assert.Regexp(t, regexp.MustCompile(`"kty":\s*"EC"`), string(dst))
	assert.Regexp(t, regexp.MustCompile(`"kid":\s*"1"`), string(dst))
	assert.Regexp(t, regexp.MustCompile(`"x":\s*"AQAB"`), string(dst))
	assert.Regexp(t, regexp.MustCompile(`"y":\s*"AQAB"`), string(dst))
	assert.Regexp(t, regexp.MustCompile(`"d":\s*"AQAB"`), string(dst))
}

func TestOct_UnmarshalJSON(t *testing.T) {
	// Setup
	const input = `
{
	"kty": "oct",
	"k": "AQAB",
	"kid": "1"
}
`
	// Act
	var oct OctSecretKey
	err := json.Unmarshal([]byte(input), &oct)

	// Assert
	assert.NoError(t, err)
	assert.Equal(t, KtyOct, oct.Kty())
	assert.Equal(t, "1", oct.Kid())
	assert.Equal(t, []byte{1, 0, 1}, oct.K.Bytes())

}

func TestOct_MarshalJSON(t *testing.T) {
	// Setup
	var oct OctSecretKey
	oct.SetKid("1")
	oct.K.SetBytes([]byte{1, 0, 1})

	// Act
	dst, err := json.Marshal(&oct)

	// Assert
	assert.NoError(t, err)
	assert.Regexp(t, regexp.MustCompile(`"kty":\s*"oct"`), string(dst))
	assert.Regexp(t, regexp.MustCompile(`"kid":\s*"1"`), string(dst))
	assert.Regexp(t, regexp.MustCompile(`"k":\s*"AQAB"`), string(dst))
}

func Test_Unmarshal(t *testing.T) {
	testCase := []struct {
		expected reflect.Type
		encoded  string
	}{
		{
			expected: reflect.TypeOf(&PublicRsaKey{}),
			encoded: `
{
	"kty": "RSA",
	"n": "BBBB",
	"e": "AQAB",
	"kid": "1"
}`,
		},
		{
			expected: reflect.TypeOf(&PublicEcKey{}),
			encoded: `
{
	"kty": "EC",
	"crv": "P-256",
	"x": "BBBB",
	"y": "AQAB",
	"kid": "1"
}`,
		},
		{
			expected: reflect.TypeOf(&OctSecretKey{}),
			encoded: `
{
	"kty": "oct",
	"k": "AQAB",
	"kid": "1"
}`,
		},
	}

	for _, test := range testCase {
		// Act
		k, e := UnmarshalJwk(bytes.NewReader([]byte(test.encoded)))

		// Assert
		assert.NoError(t, e)
		assert.Equal(t, test.expected, reflect.TypeOf(k))
	}
}

func TestJwkFields_CheckConsistency(t *testing.T) {
	// Setup
	testCases := []struct {
		field    jwkFields
		expected error
	}{
		// Duplicate KeyOps
		{
			field: jwkFields{
				KeyOps: []KeyOps{KeyOpsDecrypt, KeyOpsDecrypt},
			},
			expected: ErrDuplicateKeyOps,
		},
		// Invalid SHA1 certificate thumbprint
		{
			field: jwkFields{
				KeyX5C: []Certificate{
					{
						Certificate: &x509.Certificate{},
					},
				},
				KeyX5T: &Fingerprint{
					digest: []byte("invalid"),
				},
			},
			expected: ErrJwkInconsistentCertificateFields,
		},
	}

	// Act/Assert
	for i, test := range testCases {
		t.Run(fmt.Sprintf("%d", i+1),
			func(t *testing.T) {
				err := test.field.CheckConsistency()
				assert.Equal(t, test.expected, err)
			})
	}

}

func TestJwkFields_X5C(t *testing.T) {

	testCases := []struct {
		certs []*x509.Certificate
	}{
		{
			certs: nil,
		},
		{
			certs: []*x509.Certificate{},
		},
		{
			certs: []*x509.Certificate{
				{
					Subject: pkix.Name{
						SerialNumber: "1",
					},
				},
			},
		},
		{
			certs: []*x509.Certificate{
				{
					Subject: pkix.Name{
						SerialNumber: "2",
					},
				},
				{
					Subject: pkix.Name{
						SerialNumber: "3",
					},
				},
			},
		},
	}
	for i, test := range testCases {
		t.Run(fmt.Sprintf("%v", i+1), func(t *testing.T) {
			j := &jwkFields{}
			j.SetX5C(test.certs)
			certs := j.X5C()
			require.Equal(t, len(test.certs), len(certs))
			for i := range test.certs {
				assert.True(t, reflect.DeepEqual(test.certs[i], certs[i]))
			}
		})
	}
}
