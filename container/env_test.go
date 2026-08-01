package container

import (
	"reflect"
	"testing"
)

func TestMergeEnv(t *testing.T) {
	cases := []struct {
		name     string
		imageEnv []string
		userEnv  []string
		want     []string
	}{
		{
			name:     "user overrides image key in place",
			imageEnv: []string{"PATH=/usr/bin", "LOG_LEVEL=info"},
			userEnv:  []string{"LOG_LEVEL=debug"},
			want:     []string{"PATH=/usr/bin", "LOG_LEVEL=debug"},
		},
		{
			name:     "user-only key appended",
			imageEnv: []string{"PATH=/usr/bin"},
			userEnv:  []string{"FOO=bar"},
			want:     []string{"PATH=/usr/bin", "FOO=bar"},
		},
		{
			name:     "no image env",
			imageEnv: nil,
			userEnv:  []string{"FOO=bar"},
			want:     []string{"FOO=bar"},
		},
		{
			name:     "no user env leaves image env untouched",
			imageEnv: []string{"PATH=/usr/bin"},
			userEnv:  nil,
			want:     []string{"PATH=/usr/bin"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := mergeEnv(tc.imageEnv, tc.userEnv)
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("mergeEnv(%v, %v) = %v, want %v", tc.imageEnv, tc.userEnv, got, tc.want)
			}
		})
	}
}
