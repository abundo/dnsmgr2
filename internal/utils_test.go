package internal

import "testing"

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
