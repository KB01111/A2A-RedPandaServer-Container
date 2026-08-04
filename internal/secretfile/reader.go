package secretfile

import (
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"
)

const DefaultMaxBytes int64 = 64 * 1024

// ReadString reads a bounded operator-supplied secret from one file handle.
// A single trailing line ending is removed while all other bytes are retained.
func ReadString(path, label string, maxBytes int64) (string, error) {
	return readString(path, label, maxBytes, true)
}

// ReadPublicString reads bounded public material such as CA certificates. It
// retains regular-file and content checks but permits normal read-only public
// file modes on Unix.
func ReadPublicString(path, label string, maxBytes int64) (string, error) {
	return readString(path, label, maxBytes, false)
}

func readString(path, label string, maxBytes int64, requirePrivatePermissions bool) (string, error) {
	if strings.TrimSpace(path) == "" {
		return "", fmt.Errorf("%s file path is required", label)
	}
	if maxBytes <= 0 {
		maxBytes = DefaultMaxBytes
	}
	file, err := os.Open(path) // #nosec G304 -- the path is explicit operator configuration.
	if err != nil {
		return "", fmt.Errorf("open %s file: %w", label, err)
	}
	defer func() { _ = file.Close() }()

	info, err := file.Stat()
	if err != nil {
		return "", fmt.Errorf("stat %s file: %w", label, err)
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("%s file must be a regular file", label)
	}
	if requirePrivatePermissions && runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		return "", fmt.Errorf("%s file permissions must not grant group or other access", label)
	}
	if info.Size() > maxBytes {
		return "", fmt.Errorf("%s file exceeds %d bytes", label, maxBytes)
	}
	contents, err := io.ReadAll(io.LimitReader(file, maxBytes+1))
	if err != nil {
		return "", fmt.Errorf("read %s file: %w", label, err)
	}
	if int64(len(contents)) > maxBytes {
		return "", fmt.Errorf("%s file exceeds %d bytes", label, maxBytes)
	}
	value := strings.TrimSuffix(strings.TrimSuffix(string(contents), "\n"), "\r")
	if value == "" {
		return "", fmt.Errorf("%s file is empty", label)
	}
	if strings.IndexByte(value, 0) >= 0 {
		return "", fmt.Errorf("%s file contains a NUL byte", label)
	}
	return value, nil
}
