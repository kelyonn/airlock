package shellwords

import (
	"reflect"
	"testing"
)

func TestSplit(t *testing.T) {
	cases := []struct {
		name    string
		input   string
		want    []string
		wantErr bool
	}{
		{
			name:  "plain words",
			input: "nginx -g daemon",
			want:  []string{"nginx", "-g", "daemon"},
		},
		{
			name:  "the readme's compose example",
			input: `nginx -g "daemon off;"`,
			want:  []string{"nginx", "-g", "daemon off;"},
		},
		{
			name:  "single quotes",
			input: `sh -c 'echo hello world'`,
			want:  []string{"sh", "-c", "echo hello world"},
		},
		{
			name:  "escaped space outside quotes",
			input: `echo hello\ world`,
			want:  []string{"echo", "hello world"},
		},
		{
			name:  "escaped quote inside double quotes",
			input: `echo "say \"hi\""`,
			want:  []string{"echo", `say "hi"`},
		},
		{
			name:  "empty string",
			input: "",
			want:  nil,
		},
		{
			name:  "extra whitespace collapses",
			input: "  a   b  \t c ",
			want:  []string{"a", "b", "c"},
		},
		{
			name:  "empty quoted argument preserved",
			input: `echo "" end`,
			want:  []string{"echo", "", "end"},
		},
		{
			name:    "unterminated double quote",
			input:   `echo "unterminated`,
			wantErr: true,
		},
		{
			name:    "unterminated single quote",
			input:   `echo 'unterminated`,
			wantErr: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Split(tc.input)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("Split(%q) = %v, want error", tc.input, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("Split(%q) unexpected error: %v", tc.input, err)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("Split(%q) = %#v, want %#v", tc.input, got, tc.want)
			}
		})
	}
}
