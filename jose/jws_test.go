// SPDX-FileCopyrightText: 2026 Thales Group and the gose Contributors
// SPDX-License-Identifier: MIT

package jose

import (
	"encoding/json"
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAudiences_MarshalJSON(t *testing.T) {
	// Setup
	testCases := []struct {
		audiences []string
		expected  string
	}{
		{
			audiences: []string{"one"},
			expected:  `"one"`,
		},
		{
			audiences: []string{},
			expected:  `\[\]`,
		},
		{
			audiences: []string{"one", "two"},
			expected:  `^\[\s*"one",\s*"two"\s*\]?`,
		},
		{
			audiences: []string{},
			expected:  `^\[\]?`,
		},
	}

	// Act/Assert
	for _, test := range testCases {
		aud := Audiences{
			Aud: test.audiences,
		}
		result, err := json.Marshal(&aud)
		assert.NoError(t, err)
		assert.Regexp(t, regexp.MustCompile(test.expected), string(result))
	}
}

func TestAudiences_UnmarshalJSON(t *testing.T) {
	// Setup
	testCases := []struct {
		input    string
		expected []string
		err      error
	}{
		{
			input:    `"one"`,
			expected: []string{"one"},
			err:      nil,
		},
		{
			input:    `[]`,
			expected: nil,
			err:      nil,
		},
		{
			input:    `["one"]`,
			expected: []string{"one"},
			err:      nil,
		},
		{
			input:    `["one", "two"]`,
			expected: []string{"one", "two"},
			err:      nil,
		},
		{
			input:    `[1, "one"]`,
			expected: nil,
			err:      ErrJSONFormat,
		},
	}

	// Act/Assert
	for _, test := range testCases {
		var aud Audiences
		err := aud.UnmarshalJSON([]byte(test.input))
		assert.Equal(t, test.err, err)
		assert.Len(t, aud.Aud, len(test.expected))
		assert.Equal(t, test.expected, aud.Aud)
	}

}
