package output

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWriteAtomic_OverwriteAndPreserve(t *testing.T) {
	dir := t.TempDir()
	final := filepath.Join(dir, "out.txt")

	// create original file
	if err := os.WriteFile(final, []byte("original"), 0o644); err != nil {
		t.Fatalf("setup write original: %v", err)
	}

	// successful overwrite
	if err := WriteAtomic(final, []byte("newcontent")); err != nil {
		t.Fatalf("WriteAtomic failed: %v", err)
	}
	got, err := os.ReadFile(final)
	if err != nil {
		t.Fatalf("read final: %v", err)
	}
	if string(got) != "newcontent" {
		t.Fatalf("content mismatch: %q", string(got))
	}
}

func TestWriteAtomic_FailPreserveOriginal(t *testing.T) {
	// create a dir we cannot write into to force failure
	dir := t.TempDir()
	final := filepath.Join(dir, "out.txt")
	if err := os.WriteFile(final, []byte("original"), 0o644); err != nil {
		t.Fatalf("setup write original: %v", err)
	}

	// make dir read/execute only (no write) to cause CreateTemp to fail
	if err := os.Chmod(dir, 0o555); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	// ensure we restore perms at the end so cleanup can remove files
	t.Cleanup(func() {
		_ = os.Chmod(dir, 0o755)
	})

	err := WriteAtomic(final, []byte("should-not-write"))
	if err == nil {
		t.Fatalf("expected WriteAtomic to fail on unwritable dir")
	}

	// original file must remain unchanged
	got, rerr := os.ReadFile(final)
	if rerr != nil {
		t.Fatalf("read final: %v", rerr)
	}
	if string(got) != "original" {
		t.Fatalf("original file was modified: %q", string(got))
	}
}
