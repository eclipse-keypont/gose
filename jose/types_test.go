// SPDX-FileCopyrightText: 2026 Thales Group and the gose Contributors
// SPDX-License-Identifier: MIT

package jose

import (
	"encoding/json"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBigNum_MarshalJSON(t *testing.T) {
	// Setup
	var val BigNum
	val.SetBytes([]byte{1, 0, 1})

	// Act
	marshalled, err := json.Marshal(&val)

	// Assert
	assert.NoError(t, err)
	assert.Equal(t, `"AQAB"`, string(marshalled))

	val.SetBytes([]byte{})
	marshalled, err = json.Marshal(&val)

	assert.Nil(t, marshalled)
	assert.IsType(t, &json.MarshalerError{}, err)
	assert.Equal(t,
		"json: error calling MarshalJSON for type *jose.BigNum: invalid Blob format, may not be empty",
		err.Error())

}

func TestBigNum_UnmarshalJSON(t *testing.T) {
	// Setup
	var val BigNum
	var expected big.Int
	expected.SetInt64(65537)

	// Act
	err := json.Unmarshal([]byte(`"AQAB"`), &val)

	// Assert
	assert.NoError(t, err)
	assert.True(t, expected.Cmp(val.Int()) == 0)

	// Act/Assert
	assert.Equal(t, ErrBlobEmpty, json.Unmarshal([]byte(`""`), &val))
}
