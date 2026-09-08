package dnsmgr

import (
	"net/netip"
	"strings"
	"testing"
)

func TestResolvePrefixDefaults(t *testing.T) {
	rp, err := resolvePrefix(ConfigPrefix{Name: "192.0.2.0/24", Range: "192.0.2.100-192.0.2.200"})
	if err != nil {
		t.Fatalf("resolvePrefix: %v", err)
	}
	if rp.Prefix.String() != "192.0.2.0/24" {
		t.Errorf("prefix = %s", rp.Prefix)
	}
	if !rp.HasRange || rp.RangeStart.String() != "192.0.2.100" || rp.RangeEnd.String() != "192.0.2.200" {
		t.Errorf("range = %s - %s", rp.RangeStart, rp.RangeEnd)
	}
	if rp.Gateway.String() != "192.0.2.1" {
		t.Errorf("gateway = %s, want 192.0.2.1", rp.Gateway)
	}
	if rp.SubnetMask != "255.255.255.0" {
		t.Errorf("subnet_mask = %s, want 255.255.255.0", rp.SubnetMask)
	}
}

func TestResolvePrefixOverrides(t *testing.T) {
	rp, err := resolvePrefix(ConfigPrefix{
		Name:       "10.1.2.0/24",
		Gateway:    "10.1.2.254",
		SubnetMask: "255.255.255.0",
	})
	if err != nil {
		t.Fatalf("resolvePrefix: %v", err)
	}
	if rp.HasRange {
		t.Error("expected no range")
	}
	if rp.Gateway.String() != "10.1.2.254" {
		t.Errorf("gateway = %s", rp.Gateway)
	}
	if rp.SubnetMask != "255.255.255.0" {
		t.Errorf("subnet_mask = %s", rp.SubnetMask)
	}
}

func TestResolvePrefixRangeWithSpaces(t *testing.T) {
	rp, err := resolvePrefix(ConfigPrefix{
		Name:  "192.0.2.0/24",
		Range: "192.0.2.10 - 192.0.2.20",
	})
	if err != nil {
		t.Fatalf("resolvePrefix: %v", err)
	}
	if rp.RangeStart.String() != "192.0.2.10" || rp.RangeEnd.String() != "192.0.2.20" {
		t.Errorf("range = %s - %s", rp.RangeStart, rp.RangeEnd)
	}
}

func TestResolvePrefixErrors(t *testing.T) {
	tests := []struct {
		cfg     ConfigPrefix
		wantErr string
	}{
		{cfg: ConfigPrefix{Name: ""}, wantErr: "empty"},
		{cfg: ConfigPrefix{Name: "not-a-prefix"}, wantErr: "prefix"},
		{cfg: ConfigPrefix{Name: "192.0.2.1/24"}, wantErr: "host bits"},
		{cfg: ConfigPrefix{Name: "192.0.2.0/24", Range: "192.0.2.10"}, wantErr: "start-end"},
		{cfg: ConfigPrefix{Name: "192.0.2.0/24", Range: "10.0.0.1-10.0.0.2"}, wantErr: "outside"},
		{cfg: ConfigPrefix{Name: "192.0.2.0/24", Range: "192.0.2.20-192.0.2.10"}, wantErr: "start is after end"},
		{cfg: ConfigPrefix{Name: "192.0.2.0/24", Gateway: "not-an-ip"}, wantErr: "gateway"},
		{cfg: ConfigPrefix{Name: "192.0.2.0/24", SubnetMask: "foo"}, wantErr: "subnet_mask"},
		{cfg: ConfigPrefix{Name: "2001:db8::/64", SubnetMask: "255.255.255.0"}, wantErr: "IPv4"},
	}
	for _, tt := range tests {
		_, err := resolvePrefix(tt.cfg)
		if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
			t.Errorf("resolvePrefix(%+v) = %v, want %q", tt.cfg, err, tt.wantErr)
		}
	}
}

func TestDefaultGateway(t *testing.T) {
	p24, _ := netip.ParsePrefix("192.0.2.0/24")
	if got := defaultGateway(p24).String(); got != "192.0.2.1" {
		t.Errorf("/24 gateway = %s", got)
	}
	p32, _ := netip.ParsePrefix("192.0.2.8/32")
	if got := defaultGateway(p32).String(); got != "192.0.2.8" {
		t.Errorf("/32 gateway = %s", got)
	}
	p31, _ := netip.ParsePrefix("192.0.2.0/31")
	if got := defaultGateway(p31).String(); got != "192.0.2.0" {
		t.Errorf("/31 gateway = %s", got)
	}
}

func TestRecordHostname(t *testing.T) {
	zone := &Zone{Name: "example.com"}
	if got := recordHostname(zone, &Record{Name: "test"}); got != "test.example.com" {
		t.Errorf("got %s", got)
	}
	if got := recordHostname(zone, &Record{Name: "@"}); got != "example.com" {
		t.Errorf("got %s", got)
	}
	if got := recordHostname(zone, &Record{Name: "test.example.com."}); got != "test.example.com" {
		t.Errorf("got %s", got)
	}
}

func TestIpv4SubnetMask(t *testing.T) {
	if got := ipv4SubnetMask(24); got != "255.255.255.0" {
		t.Errorf("/24 mask = %s", got)
	}
	if got := ipv4SubnetMask(16); got != "255.255.0.0" {
		t.Errorf("/16 mask = %s", got)
	}
	if got := ipv4SubnetMask(32); got != "255.255.255.255" {
		t.Errorf("/32 mask = %s", got)
	}
}
