// SPDX-FileCopyrightText: 2026 Thales Group and the gose Contributors
// SPDX-License-Identifier: MIT

package hsm

import (
	"github.com/eclipse-keypont/crypto11/v2"

	"github.com/eclipse-keypont/gose"
)

// AsymmetricDecryptionKeyStore implements the AsymmetricDecryptionKeyStore interface providing key lookup.
//
// It resolves only the key IDs (CKA_ID) it was constructed with. The kid it is asked for
// comes from the JWE header, which the sender chooses: a store that looked up any kid on
// the token would decrypt a JWE addressed to any RSA key pair there, another
// application's or a signing key included, and its errors would tell the sender which
// key IDs exist.
type AsymmetricDecryptionKeyStore struct {
	ctx  *crypto11.Context
	kids map[string]struct{}
}

// Get returns gose.AsymmetricDecryptionKey which match the given key ID. A key ID the store
// was not constructed with returns gose.ErrUnknownKey without a lookup on the token.
func (a *AsymmetricDecryptionKeyStore) Get(kid string) (k gose.AsymmetricDecryptionKey, err error) {
	if _, ok := a.kids[kid]; !ok {
		return nil, gose.ErrUnknownKey
	}
	keyPair, err := a.ctx.FindKeyPair([]byte(kid), nil)
	if err != nil {
		return nil, err
	}
	rsaKeyPair, ok := keyPair.(crypto11.SignerDecrypter)
	if !ok {
		return nil, gose.ErrInvalidKeyType
	}
	return &AsymmetricDecryptionKey{
		kid: []byte(kid),
		ctx: a.ctx,
		key: rsaKeyPair,
	}, nil
}

// NewAsymmetricDecryptionKeyStore creates an instance of AsymmetricDecryptionKeyStore that
// resolves the RSA key pairs with the given key IDs (CKA_ID) on the token, and no others.
// With no key IDs it resolves none.
func NewAsymmetricDecryptionKeyStore(ctx *crypto11.Context, kids ...string) *AsymmetricDecryptionKeyStore {
	allowed := make(map[string]struct{}, len(kids))
	for _, kid := range kids {
		allowed[kid] = struct{}{}
	}
	return &AsymmetricDecryptionKeyStore{
		ctx:  ctx,
		kids: allowed,
	}
}
