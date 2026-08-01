package container

import "testing"

func TestParseMemoryLimit(t *testing.T) {
	cases := []struct {
		name    string
		limit   string
		want    int64
		wantErr bool
	}{
		{name: "megabytes", limit: "100m", want: 100 * 1024 * 1024},
		{name: "megabytes uppercase", limit: "256M", want: 256 * 1024 * 1024},
		{name: "gigabytes", limit: "1g", want: 1024 * 1024 * 1024},
		{name: "kilobytes", limit: "512k", want: 512 * 1024},
		{name: "raw bytes", limit: "1048576", want: 1048576},
		{name: "empty defaults to 100MB", limit: "", want: 100 * 1024 * 1024},
		{name: "whitespace trimmed", limit: "  256m  ", want: 256 * 1024 * 1024},
		{name: "garbage rejected", limit: "not-a-number", wantErr: true},
		{name: "garbage with unit suffix rejected", limit: "abcm", wantErr: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseMemoryLimit(tc.limit)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("parseMemoryLimit(%q) = %d, want error", tc.limit, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseMemoryLimit(%q) unexpected error: %v", tc.limit, err)
			}
			if got != tc.want {
				t.Errorf("parseMemoryLimit(%q) = %d, want %d", tc.limit, got, tc.want)
			}
		})
	}
}
