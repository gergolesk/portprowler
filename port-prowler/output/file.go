package output

import (
	"fmt"
	"os"
	"path/filepath"
)

// WriteAtomic writes data to path atomically:
//   - create temp file in same directory
//   - write bytes, fsync, close
//   - rename to final path (overwrite)
//
// On failure the temp file is removed and an error returned.
func WriteAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	// Ensure directory exists
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("mkdir %s: %w", dir, err)
		}
	}

	tmpF, err := os.CreateTemp(dir, "portprowler-*.tmp")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	tmpPath := tmpF.Name()

	// Ensure cleanup on error
	cleanup := func() {
		_ = tmpF.Close()
		_ = os.Remove(tmpPath)
	}

	// Write data
	if _, err := tmpF.Write(data); err != nil {
		cleanup()
		return fmt.Errorf("write temp file: %w", err)
	}

	// Sync to disk
	if err := tmpF.Sync(); err != nil {
		cleanup()
		return fmt.Errorf("sync temp file: %w", err)
	}

	// Close file
	if err := tmpF.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("close temp file: %w", err)
	}

	// Rename into place (atomic on POSIX)
	if err := os.Rename(tmpPath, path); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("rename temp -> final: %w", err)
	}

	return nil
}
