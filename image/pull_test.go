package image

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"os"
	"path/filepath"
	"testing"
)

// buildTarGz writes the given entries into a gzip-compressed tar stream.
// entries with content == nil are written as directories.
type tarEntry struct {
	name     string
	content  []byte
	linkname string
	typeflag byte
}

func buildTarGz(t *testing.T, entries []tarEntry) []byte {
	t.Helper()
	var buf bytes.Buffer
	gzw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gzw)

	for _, e := range entries {
		hdr := &tar.Header{
			Name: e.name,
			Mode: 0644,
		}
		switch {
		case e.typeflag == tar.TypeSymlink:
			hdr.Typeflag = tar.TypeSymlink
			hdr.Linkname = e.linkname
		case e.content == nil:
			hdr.Typeflag = tar.TypeDir
			hdr.Mode = 0755
		default:
			hdr.Typeflag = tar.TypeReg
			hdr.Size = int64(len(e.content))
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatalf("write header %s: %v", e.name, err)
		}
		if e.content != nil {
			if _, err := tw.Write(e.content); err != nil {
				t.Fatalf("write content %s: %v", e.name, err)
			}
		}
	}

	if err := tw.Close(); err != nil {
		t.Fatalf("close tar writer: %v", err)
	}
	if err := gzw.Close(); err != nil {
		t.Fatalf("close gzip writer: %v", err)
	}
	return buf.Bytes()
}

func TestExtractLayerTarGz_Basic(t *testing.T) {
	dest := t.TempDir()
	data := buildTarGz(t, []tarEntry{
		{name: "etc/", content: nil},
		{name: "etc/hostname", content: []byte("box\n")},
		{name: "bin/sh", content: []byte("#!/bin/sh\n")},
	})

	if err := extractLayerTarGz(bytes.NewReader(data), dest); err != nil {
		t.Fatalf("extractLayerTarGz: %v", err)
	}

	got, err := os.ReadFile(filepath.Join(dest, "etc", "hostname"))
	if err != nil {
		t.Fatalf("read extracted file: %v", err)
	}
	if string(got) != "box\n" {
		t.Errorf("hostname content = %q, want %q", got, "box\n")
	}
}

func TestExtractLayerTarGz_Whiteout(t *testing.T) {
	dest := t.TempDir()

	// First layer: creates a file.
	layer1 := buildTarGz(t, []tarEntry{
		{name: "data/", content: nil},
		{name: "data/keep.txt", content: []byte("keep")},
		{name: "data/remove.txt", content: []byte("remove me")},
	})
	if err := extractLayerTarGz(bytes.NewReader(layer1), dest); err != nil {
		t.Fatalf("extract layer1: %v", err)
	}

	// Second layer: whiteouts remove.txt via the ".wh." prefix.
	layer2 := buildTarGz(t, []tarEntry{
		{name: "data/.wh.remove.txt", content: []byte{}},
	})
	if err := extractLayerTarGz(bytes.NewReader(layer2), dest); err != nil {
		t.Fatalf("extract layer2 (whiteout): %v", err)
	}

	if _, err := os.Stat(filepath.Join(dest, "data", "remove.txt")); !os.IsNotExist(err) {
		t.Errorf("expected data/remove.txt to be removed by whiteout, stat err = %v", err)
	}
	if _, err := os.Stat(filepath.Join(dest, "data", "keep.txt")); err != nil {
		t.Errorf("expected data/keep.txt to survive, got err = %v", err)
	}
}

func TestExtractLayerTarGz_OpaqueWhiteout(t *testing.T) {
	dest := t.TempDir()

	layer1 := buildTarGz(t, []tarEntry{
		{name: "shadowed/", content: nil},
		{name: "shadowed/a.txt", content: []byte("a")},
		{name: "shadowed/b.txt", content: []byte("b")},
	})
	if err := extractLayerTarGz(bytes.NewReader(layer1), dest); err != nil {
		t.Fatalf("extract layer1: %v", err)
	}

	// Opaque whiteout clears everything previously in "shadowed/".
	layer2 := buildTarGz(t, []tarEntry{
		{name: "shadowed/.wh..wh..opq", content: []byte{}},
		{name: "shadowed/c.txt", content: []byte("c")},
	})
	if err := extractLayerTarGz(bytes.NewReader(layer2), dest); err != nil {
		t.Fatalf("extract layer2 (opaque whiteout): %v", err)
	}

	if _, err := os.Stat(filepath.Join(dest, "shadowed", "a.txt")); !os.IsNotExist(err) {
		t.Errorf("expected shadowed/a.txt to be cleared by opaque whiteout")
	}
	if _, err := os.Stat(filepath.Join(dest, "shadowed", "b.txt")); !os.IsNotExist(err) {
		t.Errorf("expected shadowed/b.txt to be cleared by opaque whiteout")
	}
	if _, err := os.Stat(filepath.Join(dest, "shadowed", "c.txt")); err != nil {
		t.Errorf("expected shadowed/c.txt (written after the opaque whiteout) to exist, got err = %v", err)
	}
}

func TestExtractLayerTarGz_RejectsPathTraversal(t *testing.T) {
	dest := t.TempDir()
	data := buildTarGz(t, []tarEntry{
		{name: "../../etc/passwd", content: []byte("root:x:0:0")},
	})

	err := extractLayerTarGz(bytes.NewReader(data), dest)
	if err == nil {
		t.Fatal("expected extractLayerTarGz to reject a path-traversal entry, got nil error")
	}

	// Make sure nothing escaped the destination directory.
	if _, statErr := os.Stat(filepath.Join(filepath.Dir(dest), "etc", "passwd")); !os.IsNotExist(statErr) {
		t.Errorf("path traversal entry appears to have escaped dest: stat err = %v", statErr)
	}
}

func TestExtractLayerTarGz_Symlink(t *testing.T) {
	dest := t.TempDir()
	data := buildTarGz(t, []tarEntry{
		{name: "bin/", content: nil},
		{name: "bin/sh", content: []byte("real shell")},
		{name: "bin/link", typeflag: tar.TypeSymlink, linkname: "sh"},
	})

	if err := extractLayerTarGz(bytes.NewReader(data), dest); err != nil {
		t.Fatalf("extractLayerTarGz: %v", err)
	}

	target, err := os.Readlink(filepath.Join(dest, "bin", "link"))
	if err != nil {
		t.Fatalf("readlink: %v", err)
	}
	if target != "sh" {
		t.Errorf("symlink target = %q, want %q", target, "sh")
	}
}
