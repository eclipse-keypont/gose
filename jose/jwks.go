// SPDX-FileCopyrightText: 2026 Thales Group and the gose Contributors
// SPDX-License-Identifier: MIT

package jose

import (
	"bytes"
	"encoding/json"
)

// Jwks key store
type Jwks struct {
	Keys []Jwk `json:"keys"`
}

// UnmarshalJSON byte slice into key store, or error
func (j *Jwks) UnmarshalJSON(data []byte) error {
	var unmarshalTo struct {
		Keys []json.RawMessage `json:"keys"`
	}
	if err := json.Unmarshal(data, &unmarshalTo); err != nil {
		return err
	}
	for _, blob := range unmarshalTo.Keys {
		jwk, err := UnmarshalJwk(bytes.NewReader(blob))
		if err != nil {
			return err
		}
		j.Keys = append(j.Keys, jwk)
	}
	return nil
}
