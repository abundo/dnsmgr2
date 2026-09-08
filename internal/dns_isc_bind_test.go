package internal

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func testBINDZone(t *testing.T, dir, name string) *Zone {
	t.Helper()
	return &Zone{
		Name:    name,
		TmpFile: filepath.Join(dir, name),
		DNS: &ConfigDNS_ZoneTemplate{
			DefaultTTL: "900",
			NS: []ConfigDNS_TemplateNS{
				{Name: "@", Type: "NS", Value: "ns1.example.net."},
			},
		},
		SOA: &ConfigDNS_SOA_template{
			Mname:   "ns1.example.net.",
			Rname:   "hostmaster.example.net.",
			Refresh: 36000,
			Retry:   3600,
			Expire:  604800,
			Minimum: 900,
		},
		Records: RecordsType{
			{Name: "mail", Type: "A", Value: "192.0.2.10"},
			{Name: "@", Type: "MX", Value: "10 mail"},
		},
	}
}

func TestUpdateZoneNamedCheckzone(t *testing.T) {
	if _, err := exec.LookPath("named-checkzone"); err != nil {
		t.Skip("named-checkzone not installed")
	}

	dir := t.TempDir()
	dns := NewISCBINDManager(DNSManagerOpt{
		Dbfile: filepath.Join(dir, "dnsmgr2.sqlite"),
	})

	valid := testBINDZone(t, dir, "example.com")
	if err := dns.UpdateZone(nil, valid, false); err != nil {
		t.Fatalf("valid zone: %v", err)
	}

	invalid := testBINDZone(t, dir, "example.com")
	invalid.TmpFile = filepath.Join(dir, "example.com-bad")
	invalid.DNS = &ConfigDNS_ZoneTemplate{
		DefaultTTL: "900",
		NS: []ConfigDNS_TemplateNS{
			{Name: "@", Type: "NS", Value: "ns1.example.com."},
		},
	}
	err := dns.UpdateZone(nil, invalid, false)
	if err == nil {
		t.Fatal("expected named-checkzone error for in-zone NS without A/AAAA")
	}
	msg := err.Error()
	if !strings.Contains(msg, "named-checkzone") {
		t.Errorf("error should mention named-checkzone: %v", err)
	}
	if !strings.Contains(msg, "no address") && !strings.Contains(msg, "NS") {
		t.Errorf("error should include named-checkzone output, got: %v", err)
	}
}

func TestNamedCheckZoneIncludesOutput(t *testing.T) {
	if _, err := exec.LookPath("named-checkzone"); err != nil {
		t.Skip("named-checkzone not installed")
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "broken")
	if err := os.WriteFile(path, []byte("this is not a zone file\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	err := namedCheckZone("example.com", path)
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "named-checkzone example.com "+path) {
		t.Errorf("error should include command args: %v", err)
	}
	if strings.TrimSpace(err.Error()) == "exit status 1" {
		t.Fatal("error hid named-checkzone output")
	}
}

func TestUpdateWritesValidAllowUpdateSyntax(t *testing.T) {
	if _, err := exec.LookPath("named-checkzone"); err != nil {
		t.Skip("named-checkzone not installed")
	}

	dir := t.TempDir()
	host := &ConfigDNS_HostTemplate{
		Type:         "isc_bind",
		Configdir:    dir,
		IncludeFile:  "named.conf.dnsmgr2",
		ZonesDir:     dir,
		Tmpdir:       dir,
		CmdReloadAll: "true",
	}
	zt := ConfigDNS_ZoneTemplate{
		SOA:            "default_soa",
		DefaultTTL:     "900",
		NS:             []ConfigDNS_TemplateNS{{Name: "@", Type: "NS", Value: "ns1.example.net."}},
		AllowUpdate:    []string{"key dhcp-key"},
		ParentalAgents: []string{"192.0.2.53"},
	}
	soa := ConfigDNS_SOA_template{
		Mname: "ns1.example.net.", Rname: "hostmaster.example.net.",
		SerialFormat: "date_serial", Refresh: 36000, Retry: 3600, Expire: 604800, Minimum: 900,
	}
	zone := &Zone{
		Name:       "example.com",
		ConfigZone: &ConfigZone{Name: "example.com", DnsTemplate: "default_dns"},
		Host:       host,
		Records:    RecordsType{{Name: "mail", Type: "A", Value: "192.0.2.10"}},
	}
	dns := NewISCBINDManager(DNSManagerOpt{
		Dbfile: filepath.Join(dir, "dnsmgr2.sqlite"),
		ConfigDNS: &ConfigDNS{
			ZoneTemplates: map[string]ConfigDNS_ZoneTemplate{"default_dns": zt},
			SOATemplates:  map[string]ConfigDNS_SOA_template{"default_soa": soa},
		},
		Zones: ZonesType{zone},
	})
	if err := dns.PreUpdate(); err != nil {
		t.Fatal(err)
	}
	if err := dns.Update(host, false); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(filepath.Join(dir, "named.conf.dnsmgr2"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(body)
	if strings.Contains(text, "{;") {
		t.Fatalf("invalid BIND brace: %s", text)
	}
	if !strings.Contains(text, "allow-update {") || !strings.Contains(text, "parental-agents {") {
		t.Fatalf("missing clauses: %s", text)
	}
}
