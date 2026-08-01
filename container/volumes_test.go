package container

import "testing"

func TestParseVolumeSpec(t *testing.T) {
	cases := []struct {
		name    string
		spec    string
		want    VolumeMount
		wantErr bool
	}{
		{
			name: "read-write",
			spec: "/host/data:/data",
			want: VolumeMount{HostPath: "/host/data", ContainerPath: "/data"},
		},
		{
			name: "read-only",
			spec: "/host/data:/data:ro",
			want: VolumeMount{HostPath: "/host/data", ContainerPath: "/data", ReadOnly: true},
		},
		{
			name:    "relative host path rejected",
			spec:    "relative/path:/data",
			wantErr: true,
		},
		{
			name:    "relative container path rejected",
			spec:    "/host/data:relative",
			wantErr: true,
		},
		{
			name:    "unknown option rejected",
			spec:    "/host/data:/data:rw",
			wantErr: true,
		},
		{
			name:    "empty spec rejected",
			spec:    "",
			wantErr: true,
		},
		{
			name:    "missing container path rejected",
			spec:    "/host/data",
			wantErr: true,
		},
		{
			name:    "too many segments rejected",
			spec:    "/a:/b:ro:extra",
			wantErr: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseVolumeSpec(tc.spec)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("ParseVolumeSpec(%q) = %+v, want error", tc.spec, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseVolumeSpec(%q) unexpected error: %v", tc.spec, err)
			}
			if got != tc.want {
				t.Errorf("ParseVolumeSpec(%q) = %+v, want %+v", tc.spec, got, tc.want)
			}
		})
	}
}
