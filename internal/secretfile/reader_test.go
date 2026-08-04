package secretfile

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestReadString(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(path, []byte(" secret with spaces \r\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	value, err := ReadString(path, "test secret", 1024)
	if err != nil {
		t.Fatalf("ReadString() error = %v", err)
	}
	if value != " secret with spaces " {
		t.Fatalf("ReadString() = %q", value)
	}
}

func TestReadStringRejectsUnsafeFiles(t *testing.T) {
	tests := []struct {
		name     string
		contents []byte
		maxBytes int64
	}{
		{name: "empty", maxBytes: 10},
		{name: "NUL", contents: []byte("bad\x00secret"), maxBytes: 20},
		{name: "oversize", contents: []byte("12345"), maxBytes: 4},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "secret")
			if err := os.WriteFile(path, test.contents, 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := ReadString(path, "test secret", test.maxBytes); err == nil {
				t.Fatal("ReadString() error = nil, want rejection")
			}
		})
	}
}

func TestReadStringRejectsMissingAndDirectory(t *testing.T) {
	if _, err := ReadString(filepath.Join(t.TempDir(), "missing"), "test secret", 10); err == nil {
		t.Fatal("missing file succeeded")
	}
	if _, err := ReadString(t.TempDir(), "test secret", 10); err == nil {
		t.Fatal("directory succeeded")
	}
}

func TestReadStringRejectsBroadUnixPermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix permission bits are not authoritative on Windows")
	}
	path := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(path, []byte("secret"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadString(path, "test secret", 10); err == nil || !strings.Contains(err.Error(), "permissions") {
		t.Fatalf("ReadString() error = %v", err)
	}
}
