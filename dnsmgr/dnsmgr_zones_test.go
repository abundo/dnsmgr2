package dnsmgr

import (
	"bytes"
	"io"
	"net/netip"
	"os"
	"strings"
	"testing"
)

func testHostTemplate() *ConfigDNS_HostTemplate {
	return &ConfigDNS_HostTemplate{
		Type:        "isc_bind",
		Configdir:   "/etc/bind",
		IncludeFile: "named.conf.dnsmgr2",
		ZonesDir:    "/var/lib/bind",
		Tmpdir:      "/tmp",
	}
}

func TestAddReverseZoneIPv4Slash8(t *testing.T) {
	dm := testDnsManager("example.com")
	err := dm.AddReverseZone(testHostTemplate(), &ConfigZone{
		Name: "10.0.0.0/8",
		Type: "reverse4",
	})
	if err != nil {
		t.Fatalf("AddReverseZone /8: %v", err)
	}
	var found *Zone
	for _, z := range *dm.Zones {
		if z.Name == "10.in-addr.arpa" {
			found = z
		}
		if z.Name == "0.10.in-addr.arpa" {
			t.Fatalf("legacy /8 zone name still used: %s", z.Name)
		}
	}
	if found == nil {
		t.Fatal("missing 10.in-addr.arpa")
	}
	addr, _ := netip.ParseAddr("10.1.2.3")
	zone, ok := dm.ZoneReverse4.Lookup(addr)
	if !ok || zone != found {
		t.Fatalf("lookup 10.1.2.3 ok=%v zone=%v", ok, zone)
	}
}

func TestAddReverseZoneFamilyMismatch(t *testing.T) {
	dm := testDnsManager("example.com")
	err := dm.AddReverseZone(testHostTemplate(), &ConfigZone{
		Name: "2001:db8::/64",
		Type: "reverse4",
	})
	if err == nil || !strings.Contains(err.Error(), "not IPv4") {
		t.Fatalf("error = %v, want not IPv4", err)
	}
}

func TestLoadZonesPropagatesReverseError(t *testing.T) {
	dm, err := NewDnsManager(ConfigRoot{
		DNS: ConfigDNS{
			HostTemplates: map[string]ConfigDNS_HostTemplate{
				"bind": {Type: "isc_bind", Configdir: "/etc/bind", IncludeFile: "named.conf.dnsmgr2", ZonesDir: "/var/lib/bind", Tmpdir: "/tmp"},
			},
		},
		Dnsmgr2: ConfigDataGroups{
			{
				HostDnsTemplate: "bind",
				Zones: []ConfigZone{
					{Name: "10.0.0.1/24", Type: "reverse4", DnsTemplate: "default_dns"},
				},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	err = dm.LoadZones()
	if err == nil || !strings.Contains(err.Error(), "host bits") {
		t.Fatalf("LoadZones = %v, want host bits error", err)
	}
}

func TestLoadZonesDuplicateForward(t *testing.T) {
	dm, err := NewDnsManager(ConfigRoot{
		DNS: ConfigDNS{
			HostTemplates: map[string]ConfigDNS_HostTemplate{
				"bind": {Type: "isc_bind", Configdir: "/etc/bind", IncludeFile: "named.conf.dnsmgr2", ZonesDir: "/var/lib/bind", Tmpdir: "/tmp"},
			},
		},
		Dnsmgr2: ConfigDataGroups{
			{
				HostDnsTemplate: "bind",
				Zones: []ConfigZone{
					{Name: "example.com", Type: "forward", DnsTemplate: "default_dns"},
					{Name: "example.com", Type: "forward", DnsTemplate: "default_dns"},
				},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	err = dm.LoadZones()
	if err == nil || !strings.Contains(err.Error(), "already exist") {
		t.Fatalf("LoadZones = %v, want already exist", err)
	}
}

func TestStatusReportsFiles(t *testing.T) {
	dir := t.TempDir()
	dm, err := NewDnsManager(ConfigRoot{
		DNS: ConfigDNS{
			HostTemplates: map[string]ConfigDNS_HostTemplate{
				"bind": {
					Type:        "isc_bind",
					Configdir:   dir,
					IncludeFile: "named.conf.dnsmgr2",
					ZonesDir:    dir,
					Tmpdir:      dir,
				},
			},
		},
		Dnsmgr2: ConfigDataGroups{
			{HostDnsTemplate: "bind", Zones: []ConfigZone{{Name: "example.com", Type: "forward", DnsTemplate: "default_dns"}}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	err = dm.Status()
	_ = w.Close()
	os.Stdout = old
	var buf bytes.Buffer
	if _, copyErr := io.Copy(&buf, r); copyErr != nil {
		t.Fatal(copyErr)
	}
	_ = r.Close()
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	out := buf.String()
	if strings.Contains(out, "not implemented") {
		t.Fatalf("status still unimplemented: %s", out)
	}
	if !strings.Contains(out, "named.conf.dnsmgr2") {
		t.Fatalf("status missing include path: %s", out)
	}
}

func TestReverseOwnerRelative(t *testing.T) {
	got, err := reverseOwnerRelative("4.2.0.192.in-addr.arpa", "2.0.192.in-addr.arpa")
	if err != nil || got != "4" {
		t.Fatalf("got %q err=%v", got, err)
	}
	got, err = reverseOwnerRelative("10.in-addr.arpa", "10.in-addr.arpa")
	if err != nil || got != "@" {
		t.Fatalf("apex got %q err=%v", got, err)
	}
	if _, err := reverseOwnerRelative("4.2.0.192.in-addr.arpa", "168.192.in-addr.arpa"); err == nil {
		t.Fatal("expected suffix error")
	}
}
