// SPDX-FileCopyrightText: 2026 Thales Group and the gose Contributors
// SPDX-License-Identifier: MIT

package jose

import (
	"encoding/json"
	"fmt"
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

func TestAudiences_UnmarshalJSON_BoundAndFormat(t *testing.T) {
	atCap := make([]string, MaxAudiences)
	for i := range atCap {
		atCap[i] = fmt.Sprintf("aud-%d", i)
	}
	atCapJSON, err := json.Marshal(atCap)
	require.NoError(t, err)
	overCapJSON, err := json.Marshal(append(atCap, "one-too-many"))
	require.NoError(t, err)

	for name, tc := range map[string]struct {
		src  string
		want []string
		err  error
	}{
		"string":        {src: `"a"`, want: []string{"a"}},
		"array":         {src: `["a","b"]`, want: []string{"a", "b"}},
		"empty array":   {src: `[]`},
		"at the cap":    {src: string(atCapJSON), want: atCap},
		"over the cap":  {src: string(overCapJSON), err: ErrInputTooLarge},
		"number":        {src: `1`, err: ErrJSONFormat},
		"object":        {src: `{"a":"b"}`, err: ErrJSONFormat},
		"number member": {src: `["a",1]`, err: ErrJSONFormat},
		"nested array":  {src: `["a",["b"]]`, err: ErrJSONFormat},
		"truncated":     {src: `["a",`, err: ErrJSONFormat},
	} {
		t.Run(name, func(t *testing.T) {
			var aud Audiences
			err := aud.UnmarshalJSON([]byte(tc.src))
			if tc.err != nil {
				require.ErrorIs(t, err, tc.err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.want, aud.Aud)
		})
	}
}
