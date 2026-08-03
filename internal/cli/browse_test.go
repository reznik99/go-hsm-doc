package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestReadInput(t *testing.T) {
	t.Run("regular file", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "key.pem")
		want := []byte("key data")
		if err := os.WriteFile(path, want, 0o600); err != nil {
			t.Fatal(err)
		}

		got, err := readInput(path)
		if err != nil {
			t.Fatalf("readInput: %v", err)
		}
		if !bytes.Equal(got, want) {
			t.Errorf("contents = %q, want %q", got, want)
		}
	})

	t.Run("directory", func(t *testing.T) {
		if _, err := readInput(t.TempDir()); err == nil {
			t.Fatal("expected an error for a directory")
		}
	})

	t.Run("too large", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "large.pem")
		if err := os.WriteFile(path, bytes.Repeat([]byte{0}, maxInputSize+1), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := readInput(path); err == nil {
			t.Fatal("expected an error for an oversized file")
		}
	})
}
