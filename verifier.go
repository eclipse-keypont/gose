// SPDX-FileCopyrightText: 2026 Thales Group and the gose Contributors
// SPDX-License-Identifier: MIT

package gose

import (
	"crypto/x509"
	"math"

	"github.com/eclipse-keypont/gose/jose"
)

var (
	validVerificationOps = []jose.KeyOps{
		jose.KeyOpsVerify,
	}
)

// NewVerificationKey for jwk or error
func NewVerificationKey(jwk jose.Jwk) (VerificationKey, error) {
	/* Check jwk can be used to verify */
	ops := validVerificationOps
	if len(jwk.Ops()) > 0 {
		ops = intersection(validVerificationOps, jwk.Ops())
		if len(ops) == 0 {
			return nil, ErrInvalidOperations
		}
	}
	switch v := jwk.(type) {
	case *jose.PublicRsaKey:
		if jwk.Alg() == "" {
			// fallback to alg from first certificate
			if certs := jwk.X5C(); len(certs) > 0 {
				switch certs[0].SignatureAlgorithm {
				case x509.SHA256WithRSA:
					jwk.SetAlg(jose.AlgRS256)
				case x509.SHA384WithRSA:
					jwk.SetAlg(jose.AlgRS384)
				case x509.SHA512WithRSA:
					jwk.SetAlg(jose.AlgRS512)
				case x509.SHA256WithRSAPSS:
					jwk.SetAlg(jose.AlgPS256)
				case x509.SHA384WithRSAPSS:
					jwk.SetAlg(jose.AlgPS384)
				case x509.SHA512WithRSAPSS:
					jwk.SetAlg(jose.AlgPS512)
				default:
				}
			}
		}
		if jwk.Alg() == jose.AlgPS256 || jwk.Alg() == jose.AlgPS384 || jwk.Alg() == jose.AlgPS512 ||
			jwk.Alg() == jose.AlgRS256 || jwk.Alg() == jose.AlgRS384 || jwk.Alg() == jose.AlgRS512 {
			if v.E.Int().Int64() > math.MaxInt32 {
				return nil, ErrInvalidExponent
			}
			var result RsaPublicKeyImpl
			result.key.N = v.N.Int()
			result.key.E = int(v.E.Int().Int64())
			result.jwk = jwk
			result.jwk.SetOps(ops)
			return &result, nil
		}
		return nil, ErrUnsupportedKeyType
	case *jose.PublicEcKey:
		if jwk.Alg() != jose.AlgES256 && jwk.Alg() != jose.AlgES384 && jwk.Alg() != jose.AlgES512 {
			return nil, ErrUnsupportedKeyType
		}
		var result ECVerificationKeyImpl
		result.key.X = v.X.Int()
		result.key.Y = v.Y.Int()
		result.key.Curve = algToOptsMap[jwk.Alg()].(*ECDSAOptions).curve
		result.jwk = jwk

		return &result, nil
		// Symmetric (oct) key verification is not supported: the VerificationKey interface
		// requires Certificates() and MarshalPem(), which have no meaningful implementation
		// for symmetric keys. Add a dedicated symmetric-verification interface if needed.
	default:
		return nil, ErrUnsupportedKeyType
	}
}
