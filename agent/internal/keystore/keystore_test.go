package keystore

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

var samplePEMs = Material{
	ClientKey:  []byte("-----BEGIN PRIVATE KEY-----\nABCD\n-----END PRIVATE KEY-----\n"),
	ClientCert: []byte("-----BEGIN CERTIFICATE-----\nEFGH\n-----END CERTIFICATE-----\n"),
	CACert:     []byte("-----BEGIN CERTIFICATE-----\nIJKL\n-----END CERTIFICATE-----\n"),
}

func TestMaterial_ValidateRejectsEmpty(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		mat  Material
	}{
		{"missing key", Material{ClientCert: []byte("x"), CACert: []byte("y")}},
		{"missing cert", Material{ClientKey: []byte("x"), CACert: []byte("y")}},
		{"missing ca", Material{ClientKey: []byte("x"), ClientCert: []byte("y")}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			if err := c.mat.Validate(); err == nil {
				t.Errorf("Validate accepted empty material: %+v", c.mat)
			}
		})
	}
}

func TestFile_SaveLoadRoundTrip(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	f := NewFile(tmp)
	if err := f.Save(samplePEMs); err != nil {
		t.Fatalf("Save: %v", err)
	}

	got, err := f.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !bytes.Equal(got.ClientKey, samplePEMs.ClientKey) {
		t.Error("ClientKey mismatch")
	}
	if !bytes.Equal(got.ClientCert, samplePEMs.ClientCert) {
		t.Error("ClientCert mismatch")
	}
	if !bytes.Equal(got.CACert, samplePEMs.CACert) {
		t.Error("CACert mismatch")
	}
}

func TestFile_LoadMissingReturnsErrNotFound(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	f := NewFile(tmp)
	_, err := f.Load()
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("Load on empty dir: err = %v, want ErrNotFound", err)
	}
}

func TestFile_SaveSetsCorrectModes(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	f := NewFile(tmp)
	if err := f.Save(samplePEMs); err != nil {
		t.Fatalf("Save: %v", err)
	}
	cases := []struct {
		name string
		mode os.FileMode
	}{
		{"client.key", 0o600},
		{"client.crt", 0o644},
		{"ca.crt", 0o644},
	}
	for _, c := range cases {
		fi, err := os.Stat(filepath.Join(tmp, c.name))
		if err != nil {
			t.Fatalf("stat %s: %v", c.name, err)
		}
		if got := fi.Mode().Perm(); got != c.mode {
			t.Errorf("%s mode = %v, want %v", c.name, got, c.mode)
		}
	}
}

func TestFile_SaveAtomicReplacesPrevious(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	f := NewFile(tmp)
	if err := f.Save(samplePEMs); err != nil {
		t.Fatalf("Save 1: %v", err)
	}
	updated := Material{
		ClientKey:  []byte("new-key"),
		ClientCert: []byte("new-cert"),
		CACert:     []byte("new-ca"),
	}
	if err := f.Save(updated); err != nil {
		t.Fatalf("Save 2: %v", err)
	}
	got, _ := f.Load()
	if !bytes.Equal(got.ClientKey, []byte("new-key")) {
		t.Error("Save didn't replace ClientKey")
	}
	// No leftover .tmp files.
	entries, _ := os.ReadDir(tmp)
	for _, e := range entries {
		if filepath.Ext(e.Name()) == ".tmp" {
			t.Errorf("leftover atomic-rename file: %s", e.Name())
		}
	}
}

func TestAutoSelect_ReturnsAStore(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	s := AutoSelect(tmp)
	if s == nil {
		t.Fatal("AutoSelect returned nil")
	}
	// On Linux runners with a usable keyring this is "kernel-keyring";
	// in CI containers without /proc/keys it's "file". Either is fine
	// — the contract is "you get a working Store".
	if name := s.Name(); name != "kernel-keyring" && name != "file" {
		t.Errorf("AutoSelect.Name = %q, want kernel-keyring or file", name)
	}
	// The chosen store must round-trip our sample material.
	if err := s.Save(samplePEMs); err != nil {
		t.Fatalf("AutoSelect Save: %v", err)
	}
	got, err := s.Load()
	if err != nil {
		t.Fatalf("AutoSelect Load: %v", err)
	}
	if !bytes.Equal(got.ClientCert, samplePEMs.ClientCert) {
		t.Error("AutoSelect round-trip lost ClientCert content")
	}
}
