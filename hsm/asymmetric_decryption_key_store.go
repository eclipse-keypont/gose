// SPDX-FileCopyrightText: 2026 Thales Group and the gose Contributors
// SPDX-License-Identifier: MIT

package hsm

import (
	"github.com/eclipse-keypont/crypto11/v2"

	"github.com/eclipse-keypont/gose"
)

// AsymmetricDecryptionKeyStore implements the AsymmetricDecryptionKeyStore interface providing key lookup
type AsymmetricDecryptionKeyStore struct {
	ctx *crypto11.Context
}

// Get returns gose.AsymmetricDecryptionKey which match the given key ID.
func (a *AsymmetricDecryptionKeyStore) Get(kid string) (k gose.AsymmetricDecryptionKey, err error) {
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

// NewAsymmetricDecryptionKeyStore creates an instance of AsymmetricDecryptionKeyStore.
func NewAsymmetricDecryptionKeyStore(ctx *crypto11.Context) *AsymmetricDecryptionKeyStore {
	return &AsymmetricDecryptionKeyStore{
		ctx: ctx,
	}
}
