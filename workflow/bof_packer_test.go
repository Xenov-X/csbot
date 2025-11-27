package workflow

import (
	"encoding/base64"
	"testing"
)

func TestPackBOFArguments(t *testing.T) {
	tests := []struct {
		name     string
		args     []BOFArgument
		expected string // base64 encoded
	}{
		{
			name: "zs - string + short",
			args: []BOFArgument{
				{Type: "string", Value: "C:\\Windows"},
				{Type: "short", Value: 0},
			},
			expected: "AAAAC0M6XFdpbmRvd3MAAAA=",
		},
		{
			name: "Zs - wstring + short",
			args: []BOFArgument{
				{Type: "wstring", Value: "C:\\Windows"},
				{Type: "short", Value: 0},
			},
			expected: "AAAAFkMAOgBcAFcAaQBuAGQAbwB3AHMAAAAAAA==",
		},
		{
			name: "Zi - wstring + int",
			args: []BOFArgument{
				{Type: "wstring", Value: "C:\\Windows"},
				{Type: "int", Value: 12112},
			},
			expected: "AAAAFkMAOgBcAFcAaQBuAGQAbwB3AHMAAAAAAC9Q",
		},
		{
			name: "ZzZzi - complex with multiple strings",
			args: []BOFArgument{
				{Type: "wstring", Value: "C:\\Windows"},
				{Type: "string", Value: "C:\\Windows"},
				{Type: "wstring", Value: "C:\\Windows"},
				{Type: "string", Value: "C:\\Windows"},
				{Type: "int", Value: 12112},
			},
			expected: "AAAAFkMAOgBcAFcAaQBuAGQAbwB3AHMAAAAAAAALQzpcV2luZG93cwAAAAAWQwA6AFwAVwBpAG4AZABvAHcAcwAAAAAAAAtDOlxXaW5kb3dzAAAAL1A=",
		},
		{
			name: "iZi - int + wstring + int",
			args: []BOFArgument{
				{Type: "int", Value: 12112},
				{Type: "wstring", Value: "C:\\Windows"},
				{Type: "int", Value: 12112},
			},
			expected: "AAAvUAAAABZDADoAXABXAGkAbgBkAG8AdwBzAAAAAAAvUA==",
		},
		{
			name: "iiiZi - multiple ints + wstring + int",
			args: []BOFArgument{
				{Type: "int", Value: 12112},
				{Type: "int", Value: 12112},
				{Type: "int", Value: 12112},
				{Type: "wstring", Value: "C:\\Windows"},
				{Type: "int", Value: 12112},
			},
			expected: "AAAvUAAAL1AAAC9QAAAAFkMAOgBcAFcAaQBuAGQAbwB3AHMAAAAAAC9Q",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			packed, err := PackBOFArguments(tt.args)
			if err != nil {
				t.Fatalf("PackBOFArguments() error = %v", err)
			}

			got := base64.StdEncoding.EncodeToString(packed)
			if got != tt.expected {
				t.Errorf("PackBOFArguments() = %v, want %v", got, tt.expected)

				// Detailed comparison
				gotBytes, _ := base64.StdEncoding.DecodeString(got)
				wantBytes, _ := base64.StdEncoding.DecodeString(tt.expected)
				t.Errorf("Got bytes:  %x", gotBytes)
				t.Errorf("Want bytes: %x", wantBytes)
			}
		})
	}
}
