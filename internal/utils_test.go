package internal

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGetMACaddress(t *testing.T) {
	tests := []struct {
		in      string
		want    string
		wantErr bool
	}{
		{in: "aa:bb:cc:dd:ee:ff", want: "aa:bb:cc:dd:ee:ff"},
		{in: "AA-BB-CC-DD-EE-FF", want: "aa:bb:cc:dd:ee:ff"},
		{in: "aabb.ccdd.eeff", want: "aa:bb:cc:dd:ee:ff"},
		{in: "aabbccddeeff", want: "aa:bb:cc:dd:ee:ff"},
		{in: " 02:00:00:00:00:04 ", want: "02:00:00:00:00:04"},
		{in: "", wantErr: true},
		{in: "aa:bb:cc:dd:ee", wantErr: true},
		{in: "aa:bb:cc:dd:ee:fg", wantErr: true},
		{in: "not-a-mac", wantErr: true},
	}
	for _, tt := range tests {
		got, err := GetMACaddress(tt.in)
		if tt.wantErr {
			if err == nil {
				t.Errorf("GetMACaddress(%q) = %q, want error", tt.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("GetMACaddress(%q) unexpected error: %v", tt.in, err)
			continue
		}
		if got != tt.want {
			t.Errorf("GetMACaddress(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestRunCommand(t *testing.T) {
	if err := RunCommand("true"); err != nil {
		t.Errorf("RunCommand(true) = %v", err)
	}
	if err := RunCommand(""); err == nil {
		t.Error("RunCommand empty: expected error")
	}
	if err := RunCommand("false"); err == nil {
		t.Error("RunCommand false: expected error")
	}
}

func TestVerifyDnsname(t *testing.T) {
	ok := []string{"example.com", "example.com.", "@", "_443._tcp.www", "*.example.com", "ns1"}
	for _, n := range ok {
		if err := VerifyDnsname(n); err != nil {
			t.Errorf("VerifyDnsname(%q) = %v", n, err)
		}
	}
	bad := []string{"", "foo/bar", "foo..bar", "a\nb", "../etc", strings.Repeat("a", 64) + ".com"}
	for _, n := range bad {
		if err := VerifyDnsname(n); err == nil {
			t.Errorf("VerifyDnsname(%q) = nil, want error", n)
		}
	}
}

func TestSafeJoin(t *testing.T) {
	dir := t.TempDir()
	got, err := SafeJoin(dir, "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if got != filepath.Join(dir, "example.com") {
		t.Errorf("got %s", got)
	}
	if _, err := SafeJoin(dir, "../etc/passwd"); err == nil {
		t.Fatal("expected escape error")
	}
	if _, err := SafeJoin(dir, "/etc/passwd"); err == nil {
		t.Fatal("expected absolute path error")
	}
}

func TestCopyFileAtomicAndFilesEqual(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src")
	dst := filepath.Join(dir, "dst")
	if err := os.WriteFile(src, []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}
	equal, err := FilesEqual(src, dst)
	if err != nil {
		t.Fatal(err)
	}
	if equal {
		t.Fatal("missing dst should not be equal")
	}
	if err := CopyFile(src, dst); err != nil {
		t.Fatal(err)
	}
	equal, err = FilesEqual(src, dst)
	if err != nil || !equal {
		t.Fatalf("equal=%v err=%v", equal, err)
	}
	if err := os.WriteFile(src, []byte("world"), 0o644); err != nil {
		t.Fatal(err)
	}
	equal, err = FilesEqual(src, dst)
	if err != nil || equal {
		t.Fatalf("changed src should differ, equal=%v err=%v", equal, err)
	}
}

func TestGetSerial(t *testing.T) {
	dir := t.TempDir()
	db, err := ConnectMigrate(filepath.Join(dir, "dnsmgr2.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer CloseDB(db)

	s1, err := GetSerial(db, "example.com", false)
	if err != nil {
		t.Fatal(err)
	}
	if len(s1) != 10 {
		t.Errorf("serial %q", s1)
	}
	s2, err := GetSerial(db, "example.com", true)
	if err != nil {
		t.Fatal(err)
	}
	if s2 == s1 {
		t.Errorf("next serial did not increment: %s", s2)
	}
	if _, err := GetSerial(nil, "example.com", false); err == nil {
		t.Fatal("expected nil db error")
	}
}

func TestAcquireLock(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "dnsmgr2.lock")
	a, err := AcquireLock(path)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	if _, err := AcquireLock(path); err == nil {
		t.Fatal("expected second lock to fail")
	}
}
