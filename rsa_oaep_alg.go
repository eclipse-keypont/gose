// SPDX-FileCopyrightText: 2026 Thales Group and the gose Contributors
// SPDX-License-Identifier: MIT

package gose

import (
	"crypto"
	// Link the digests advertised by oaepAlgToHash so that crypto.Hash.New never
	// panics on an unavailable implementation.
	_ "crypto/sha1"
	_ "crypto/sha256"

	"github.com/eclipse-keypont/gose/jose"
)

// oaepAlgToHash maps the RFC 7518 §4.3 "alg" header values for RSAES-OAEP onto the
// digest each one mandates. RFC 7518 registers exactly these two; there is no
// registered OAEP variant for SHA-384 or SHA-512.
var oaepAlgToHash = map[jose.Alg]crypto.Hash{
	jose.AlgRSAOAEPSHA1: crypto.SHA1,
	jose.AlgRSAOAEPSHA2: crypto.SHA256,
}

// oaepHashToAlg is the inverse of oaepAlgToHash.
var oaepHashToAlg = map[crypto.Hash]jose.Alg{
	crypto.SHA1:   jose.AlgRSAOAEPSHA1,
	crypto.SHA256: jose.AlgRSAOAEPSHA2,
}

// OaepHashFromAlg returns the OAEP digest mandated by the given RFC 7518 §4.3 "alg"
// header value. It reports false for any alg that does not name an RSAES-OAEP
// algorithm.
func OaepHashFromAlg(alg jose.Alg) (crypto.Hash, bool) {
	hash, ok := oaepAlgToHash[alg]
	return hash, ok
}

// OaepAlgFromHash returns the RFC 7518 §4.3 "alg" header value describing RSAES-OAEP
// with the given digest. It reports false for digests RFC 7518 does not register an
// OAEP algorithm for.
func OaepAlgFromHash(hash crypto.Hash) (jose.Alg, bool) {
	alg, ok := oaepHashToAlg[hash]
	return alg, ok
}

// isRsaOaepAlg reports whether alg names one of the RSAES-OAEP key encryption
// algorithms.
func isRsaOaepAlg(alg jose.Alg) bool {
	_, ok := oaepAlgToHash[alg]
	return ok
}
