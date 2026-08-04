package rootfs

import (
	"runtime"
	"strings"
	"testing"
)

// TestAlpineRootfsURLMatchesRunningArch guards the specific bug this
// replaced: the URL used to hardcode x86_64, so an arm64 host silently
// downloaded a rootfs whose binaries could not execute at all. Asserting
// against runtime.GOARCH (rather than a fixed expected string) means this
// test travels with the binary — it fails on whichever architecture the
// mapping is wrong for, which is exactly how the original bug hid: correct
// on the machine the tests ran on, wrong everywhere else.
func TestAlpineRootfsURLMatchesRunningArch(t *testing.T) {
	url, err := alpineRootfsURL()
	if err != nil {
		if _, supported := alpineArch[runtime.GOARCH]; supported {
			t.Fatalf("alpineRootfsURL() failed on supported arch %q: %v", runtime.GOARCH, err)
		}
		t.Skipf("no Alpine mini-rootfs mapping for %q, which is a documented limitation", runtime.GOARCH)
	}

	want := alpineArch[runtime.GOARCH]
	if !strings.Contains(url, "/"+want+"/") {
		t.Errorf("URL %q does not select the %q release directory (running on GOARCH=%q)", url, want, runtime.GOARCH)
	}
	if !strings.Contains(url, "-"+want+".tar.gz") {
		t.Errorf("URL %q does not name the %q tarball (running on GOARCH=%q)", url, want, runtime.GOARCH)
	}

	// The original bug was x86_64 appearing on a non-x86_64 host. Assert the
	// other architecture's name is absent entirely, so a half-updated URL
	// (path fixed, filename not, or vice versa) is caught too.
	for goarch, alpine := range alpineArch {
		if goarch == runtime.GOARCH {
			continue
		}
		if strings.Contains(url, alpine) {
			t.Errorf("URL %q references foreign architecture %q while running on %q", url, alpine, runtime.GOARCH)
		}
	}
}

func TestAlpineRootfsURLRejectsUnknownArch(t *testing.T) {
	// Direct table check rather than calling alpineRootfsURL, since
	// runtime.GOARCH can't be varied at runtime. The contract that matters:
	// unknown architectures are absent from the map, so the lookup fails and
	// the caller errors out instead of defaulting to some arbitrary arch.
	for _, arch := range []string{"riscv64", "ppc64le", "s390x", "386", ""} {
		if _, ok := alpineArch[arch]; ok {
			t.Errorf("alpineArch unexpectedly claims support for %q — an unsupported arch must fail loudly, not fall back to a wrong-architecture rootfs", arch)
		}
	}
}

// TestCacheDirIsArchSpecific guards the upgrade path: a machine that ran the
// previous version on arm64 has a fully-extracted x86_64 rootfs cached under
// the old shared "alpine" path, marker file and all. Sharing that path would
// make Ensure take its cache-hit branch and keep returning the unusable
// rootfs even with the URL corrected.
func TestCacheDirIsArchSpecific(t *testing.T) {
	dir, err := CacheDir()
	if err != nil {
		t.Fatalf("CacheDir() failed: %v", err)
	}
	if !strings.HasSuffix(dir, "alpine-"+runtime.GOARCH) {
		t.Errorf("CacheDir() = %q, want it to end in %q", dir, "alpine-"+runtime.GOARCH)
	}
}
