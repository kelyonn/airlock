package container

import "testing"

func TestUserNSBaseIndexRoundTrip(t *testing.T) {
	for _, idx := range []int{0, 1, 2, 17, userNSMaxIndex} {
		base := userNSBaseForIndex(idx)
		got, ok := userNSIndexForBase(base)
		if !ok {
			t.Fatalf("userNSIndexForBase(%d) reported invalid, want index %d", base, idx)
		}
		if got != idx {
			t.Errorf("round trip for index %d: got %d (base %d)", idx, got, base)
		}
	}
}

func TestUserNSIndexForBaseRejectsInvalid(t *testing.T) {
	cases := []struct {
		name string
		base int
	}{
		// Below the start of the allocatable space entirely — a real system
		// account, not something airlock ever hands out.
		{name: "below offset", base: 1000},
		{name: "zero", base: 0},
		// Inside the space but not on a range boundary: a hand-edited state
		// file or one written by a build using a different range size.
		{name: "misaligned", base: userNSHostIDOffset + 1},
		{name: "misaligned mid-range", base: userNSHostIDOffset + userNSIDRangeSize/2},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if idx, ok := userNSIndexForBase(tc.base); ok {
				t.Errorf("userNSIndexForBase(%d) = %d, true; want invalid", tc.base, idx)
			}
		})
	}
}

func TestUserNSRangesDoNotOverlap(t *testing.T) {
	// Adjacent ranges must not overlap, or two containers would share UIDs
	// at the seam — the exact isolation failure private ranges exist to fix.
	for idx := 0; idx < 8; idx++ {
		end := userNSBaseForIndex(idx) + userNSIDRangeSize - 1
		next := userNSBaseForIndex(idx + 1)
		if next <= end {
			t.Fatalf("range %d ends at %d but range %d starts at %d (overlap)", idx, end, idx+1, next)
		}
	}
}

func TestNextFreeUserNSIndex(t *testing.T) {
	cases := []struct {
		name  string
		hint  int
		inUse map[int]bool
		want  int
	}{
		{
			name: "empty state takes the first private index",
			hint: userNSFirstPrivateIndex,
			want: userNSFirstPrivateIndex,
		},
		{
			name:  "skips indexes held by live containers",
			hint:  1,
			inUse: map[int]bool{1: true, 2: true},
			want:  3,
		},
		{
			name:  "honors the hint rather than always restarting at 1",
			hint:  5,
			inUse: map[int]bool{1: true},
			want:  5,
		},
		{
			// A freed range (its container exited) is reusable: the hint has
			// moved past it, so this only works by wrapping around.
			name:  "wraps around to reuse a freed range",
			hint:  userNSMaxIndex,
			inUse: map[int]bool{userNSMaxIndex: true, 1: true},
			want:  2,
		},
		{
			name: "hint below the private floor is clamped",
			hint: 0,
			want: userNSFirstPrivateIndex,
		},
		{
			name: "hint past the ceiling is clamped",
			hint: userNSMaxIndex + 99,
			want: userNSFirstPrivateIndex,
		},
		{
			name: "negative hint is clamped",
			hint: -7,
			want: userNSFirstPrivateIndex,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := nextFreeUserNSIndex(tc.hint, tc.inUse)
			if err != nil {
				t.Fatalf("nextFreeUserNSIndex(%d, %v) unexpected error: %v", tc.hint, tc.inUse, err)
			}
			if got != tc.want {
				t.Errorf("nextFreeUserNSIndex(%d, %v) = %d, want %d", tc.hint, tc.inUse, got, tc.want)
			}
			if got == userNSSharedIndex {
				t.Errorf("handed out the shared index %d, which must stay reserved", userNSSharedIndex)
			}
		})
	}
}

func TestNextFreeUserNSIndexExhausted(t *testing.T) {
	inUse := make(map[int]bool, userNSMaxIndex)
	for i := userNSFirstPrivateIndex; i <= userNSMaxIndex; i++ {
		inUse[i] = true
	}
	if got, err := nextFreeUserNSIndex(userNSFirstPrivateIndex, inUse); err == nil {
		t.Fatalf("nextFreeUserNSIndex with every range in use = %d, want error", got)
	}
}

func TestNextFreeUserNSIndexNeverReturnsSharedIndex(t *testing.T) {
	// The shared index is reserved for containers running against a shared
	// rootfs. Even with every private range taken, allocation must fail
	// rather than fall back onto it silently — a caller that got it would
	// believe it had private identity while sharing one.
	inUse := make(map[int]bool, userNSMaxIndex)
	for i := userNSFirstPrivateIndex; i <= userNSMaxIndex; i++ {
		inUse[i] = true
	}
	inUse[userNSSharedIndex] = false

	if got, err := nextFreeUserNSIndex(userNSSharedIndex, inUse); err == nil {
		t.Fatalf("nextFreeUserNSIndex = %d, want error rather than the reserved shared index", got)
	}
}
