package dnsmgr

import (
	"strings"
	"testing"

	"github.com/gaissmai/bart"
)

func testDnsManager(domain string) *DnsManager {
	dm := &DnsManager{
		Zones:        new(ZonesType),
		ZonesForward: new(ZonesType),
		ZoneReverse4: new(bart.Table[*Zone]),
		ZoneReverse6: new(bart.Table[*Zone]),
	}
	z := &Zone{Name: domain}
	*dm.Zones = append(*dm.Zones, z)
	*dm.ZonesForward = append(*dm.ZonesForward, z)
	return dm
}

func TestVerifyMX(t *testing.T) {
	tests := []struct {
		value   string
		wantErr string
	}{
		{value: "10 mail"},
		{value: "0 mail.example.com."},
		{value: "65535 mx1"},
		{value: "10", wantErr: "priority and destination"},
		{value: "10 mail extra", wantErr: "priority and destination"},
		{value: "65536 mail", wantErr: "0-65535"},
		{value: "-1 mail", wantErr: "0-65535"},
		{value: "prio mail", wantErr: "0-65535"},
		{value: "10 192.0.2.1", wantErr: "not an IP address"},
		{value: "10 2001:db8::1", wantErr: "not an IP address"},
		{value: "10 .", wantErr: "empty"},
	}
	for _, tt := range tests {
		err := verifyMX(tt.value)
		if tt.wantErr == "" {
			if err != nil {
				t.Errorf("verifyMX(%q) unexpected error: %v", tt.value, err)
			}
			continue
		}
		if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
			t.Errorf("verifyMX(%q) error = %v, want %q", tt.value, err, tt.wantErr)
		}
	}
}

func TestVerifyTLSA(t *testing.T) {
	sha256 := strings.Repeat("ab", 32)
	sha512 := strings.Repeat("cd", 64)
	tests := []struct {
		value   string
		wantErr string
	}{
		{value: "3 1 1 " + sha256},
		{value: "0 0 2 " + sha512},
		{value: "3 1 0 aabbccdd"},
		{value: "3 1 1 " + "aa:bb:" + strings.Repeat("cc", 30)},
		{value: "3 1", wantErr: "usage, selector"},
		{value: "256 1 1 " + sha256, wantErr: "usage"},
		{value: "3 256 1 " + sha256, wantErr: "selector"},
		{value: "3 1 256 " + sha256, wantErr: "matching-type"},
		{value: "3 1 1 not-hex", wantErr: "hexadecimal"},
		{value: "3 1 1 aabb", wantErr: "32 bytes"},
		{value: "3 1 2 " + sha256, wantErr: "64 bytes"},
	}
	for _, tt := range tests {
		err := verifyTLSA(tt.value)
		if tt.wantErr == "" {
			if err != nil {
				t.Errorf("verifyTLSA(%q) unexpected error: %v", tt.value, err)
			}
			continue
		}
		if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
			t.Errorf("verifyTLSA(%q) error = %v, want %q", tt.value, err, tt.wantErr)
		}
	}
}

func TestVerifyTXT(t *testing.T) {
	tests := []struct {
		value   string
		wantErr string
	}{
		{value: `"v=spf1 mx -all"`},
		{value: `""`},
		{value: `"hello  world"`},
		{value: `"foo" "bar"`},
		{value: `"say \"hi\""`},
		{value: `v=spf1 mx -all`, wantErr: "double quote"},
		{value: `"unclosed`, wantErr: "unclosed"},
		{value: `"ok" extra`, wantErr: "double quote"},
		{value: `"` + strings.Repeat("a", 256) + `"`, wantErr: "255"},
		{value: "", wantErr: "empty"},
	}
	for _, tt := range tests {
		err := verifyTXT(tt.value)
		if tt.wantErr == "" {
			if err != nil {
				t.Errorf("verifyTXT(%q) unexpected error: %v", tt.value, err)
			}
			continue
		}
		if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
			t.Errorf("verifyTXT(%q) error = %v, want %q", tt.value, err, tt.wantErr)
		}
	}
}

func TestVerifyRecordsMXDestination(t *testing.T) {
	t.Run("in-zone A target", func(t *testing.T) {
		dm := testDnsManager("example.com")
		zone := (*dm.Zones)[0]
		zone.Records = RecordsType{
			{Name: "@", Type: "MX", Value: "10 mail", Forward: true},
			{Name: "mail", Type: "A", Value: "192.0.2.10", Forward: true},
		}
		if err := dm.VerifyRecords(); err != nil {
			t.Fatalf("VerifyRecords() = %v", err)
		}
	})

	t.Run("absolute in-zone target", func(t *testing.T) {
		dm := testDnsManager("example.com")
		zone := (*dm.Zones)[0]
		zone.Records = RecordsType{
			{Name: "@", Type: "MX", Value: "10 mail.example.com.", Forward: true},
			{Name: "mail", Type: "AAAA", Value: "2001:db8::10", Forward: true},
		}
		if err := dm.VerifyRecords(); err != nil {
			t.Fatalf("VerifyRecords() = %v", err)
		}
	})

	t.Run("external target allowed", func(t *testing.T) {
		dm := testDnsManager("example.com")
		zone := (*dm.Zones)[0]
		zone.Records = RecordsType{
			{Name: "@", Type: "MX", Value: "10 aspmx.l.google.com.", Forward: true},
		}
		if err := dm.VerifyRecords(); err != nil {
			t.Fatalf("VerifyRecords() = %v", err)
		}
	})

	t.Run("missing A/AAAA", func(t *testing.T) {
		dm := testDnsManager("example.com")
		zone := (*dm.Zones)[0]
		zone.Records = RecordsType{
			{Name: "@", Type: "MX", Value: "10 mail", Forward: true},
		}
		err := dm.VerifyRecords()
		if err == nil || !strings.Contains(err.Error(), "A/AAAA") {
			t.Fatalf("VerifyRecords() = %v, want A/AAAA error", err)
		}
	})

	t.Run("CNAME target rejected", func(t *testing.T) {
		dm := testDnsManager("example.com")
		zone := (*dm.Zones)[0]
		zone.Records = RecordsType{
			{Name: "@", Type: "MX", Value: "10 mail", Forward: true},
			{Name: "mail", Type: "CNAME", Value: "other", Forward: true},
		}
		err := dm.VerifyRecords()
		if err == nil || !strings.Contains(err.Error(), "CNAME") {
			t.Fatalf("VerifyRecords() = %v, want CNAME error", err)
		}
	})
}

func TestVerifySRVAndSSHFPAndTTL(t *testing.T) {
	if err := verifySRV("10 20 443 target.example.com."); err != nil {
		t.Errorf("verifySRV: %v", err)
	}
	if err := verifySRV("10 20"); err == nil {
		t.Error("expected SRV error")
	}
	fp := strings.Repeat("ab", 32)
	if err := verifySSHFP("4 2 " + fp); err != nil {
		t.Errorf("verifySSHFP: %v", err)
	}
	if err := verifySSHFP("4 2 zz"); err == nil {
		t.Error("expected SSHFP hex error")
	}

	dm := testDnsManager("example.com")
	zone := (*dm.Zones)[0]
	zone.Records = RecordsType{
		{Name: "www", Type: "A", Value: "192.0.2.4", TTL: 86400, Forward: true},
	}
	if err := dm.VerifyRecords(); err != nil {
		t.Fatalf("TTL 86400 should be allowed: %v", err)
	}
	zone.Records[0].TTL = maxTTL + 1
	if err := dm.VerifyRecords(); err == nil {
		t.Fatal("expected TTL too large")
	}
}

func TestAddReverseRecordSkipsMissingZone(t *testing.T) {
	dm := testDnsManager("example.com")
	if err := dm.AddReverseZone(testHostTemplate(), &ConfigZone{
		Name: "192.0.2.0/24",
		Type: "reverse4",
	}); err != nil {
		t.Fatalf("AddReverseZone: %v", err)
	}

	covered := &Record{Name: "host", Type: "A", Value: "192.0.2.4", Reverse: true}
	if err := dm.AddForwardRecord("example.com", covered); err != nil {
		t.Fatalf("covered A: %v", err)
	}
	uncovered4 := &Record{Name: "other", Type: "A", Value: "198.51.100.1", Reverse: true}
	if err := dm.AddForwardRecord("example.com", uncovered4); err != nil {
		t.Fatalf("uncovered A: %v", err)
	}
	uncovered6 := &Record{Name: "v6", Type: "AAAA", Value: "2a00:ff40:0:1::127", Reverse: true}
	if err := dm.AddForwardRecord("example.com", uncovered6); err != nil {
		t.Fatalf("uncovered AAAA: %v", err)
	}

	var ptrs int
	for _, zone := range *dm.Zones {
		for _, rec := range zone.Records {
			if rec.Type == "PTR" {
				ptrs++
			}
		}
	}
	if ptrs != 1 {
		t.Fatalf("PTR count = %d, want 1 (only the covered address)", ptrs)
	}
}

func TestVerifyRecordsTLSAAndTXT(t *testing.T) {
	dm := testDnsManager("example.com")
	zone := (*dm.Zones)[0]
	zone.Records = RecordsType{
		{Name: "@", Type: "TXT", Value: `"v=spf1 mx -all"`, Forward: true},
		{Name: "_443._tcp.www", Type: "TLSA", Value: "3 1 1 " + strings.Repeat("ab", 32), Forward: true},
	}
	if err := dm.VerifyRecords(); err != nil {
		t.Fatalf("VerifyRecords() = %v", err)
	}
}
