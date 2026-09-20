package dnsmgr

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeInclude(t *testing.T, dir, name, body string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadZoneIncludesMappingAndList(t *testing.T) {
	dir := t.TempDir()
	writeInclude(t, dir, "extra.yaml", `
zones:
  - name: extra.example
    type: forward
    dns_template: default_dns
prefixes:
  - name: 192.0.2.0/24
`)
	writeInclude(t, dir, "list.yaml", `
- name: list.example
  type: forward
  dns_template: default_dns
`)
	cfg := ConfigRoot{
		Dnsmgr2: ConfigDataGroups{
			{
				HostDnsTemplate: "bind",
				Zones: []ConfigZone{
					{Name: "inline.example", Type: "forward", DnsTemplate: "default_dns"},
				},
			},
			{Include: IncludePaths{"extra.yaml", "list.yaml"}},
		},
	}
	if err := LoadZoneIncludes(&cfg, dir); err != nil {
		t.Fatal(err)
	}
	if len(cfg.Dnsmgr2) != 1 {
		t.Fatalf("include item should be merged away: %#v", cfg.Dnsmgr2)
	}
	got := cfg.Dnsmgr2[0]
	if len(got.Include) != 0 {
		t.Fatalf("include not cleared: %#v", got.Include)
	}
	if got.HostDnsTemplate != "bind" {
		t.Fatalf("host template = %q", got.HostDnsTemplate)
	}
	if len(got.Zones) != 3 {
		t.Fatalf("zones = %#v", got.Zones)
	}
	if got.Zones[0].Name != "inline.example" || got.Zones[1].Name != "extra.example" || got.Zones[2].Name != "list.example" {
		t.Fatalf("zone order = %#v", got.Zones)
	}
	if len(got.Prefixes) != 1 || got.Prefixes[0].Name != "192.0.2.0/24" {
		t.Fatalf("prefixes = %#v", got.Prefixes)
	}

	// Second call is a no-op once include is cleared.
	if err := LoadZoneIncludes(&cfg, dir); err != nil {
		t.Fatal(err)
	}
	if len(cfg.Dnsmgr2[0].Zones) != 3 {
		t.Fatalf("second load duplicated zones: %#v", cfg.Dnsmgr2[0].Zones)
	}
}

func TestLoadZoneIncludesNestedAndCycle(t *testing.T) {
	dir := t.TempDir()
	writeInclude(t, dir, "child.yaml", `
zones:
  - name: child.example
    type: forward
    dns_template: default_dns
`)
	writeInclude(t, dir, "parent.yaml", `
include:
  - child.yaml
zones:
  - name: parent.example
    type: forward
    dns_template: default_dns
`)
	cfg := ConfigRoot{
		Dnsmgr2: ConfigDataGroups{
			{HostDnsTemplate: "bind"},
			{Include: IncludePaths{"parent.yaml"}},
		},
	}
	if err := LoadZoneIncludes(&cfg, dir); err != nil {
		t.Fatal(err)
	}
	if len(cfg.Dnsmgr2[0].Zones) != 2 {
		t.Fatalf("nested zones = %#v", cfg.Dnsmgr2[0].Zones)
	}

	writeInclude(t, dir, "loop-a.yaml", "include:\n  - loop-b.yaml\n")
	writeInclude(t, dir, "loop-b.yaml", "include:\n  - loop-a.yaml\n")
	loop := ConfigRoot{
		Dnsmgr2: ConfigDataGroups{
			{HostDnsTemplate: "bind"},
			{Include: IncludePaths{"loop-a.yaml"}},
		},
	}
	err := LoadZoneIncludes(&loop, dir)
	if err == nil || !strings.Contains(err.Error(), "cycle") {
		t.Fatalf("cycle error = %v", err)
	}
}

func TestLoadZoneIncludesMissingAndEmpty(t *testing.T) {
	dir := t.TempDir()
	cfg := ConfigRoot{
		Dnsmgr2: ConfigDataGroups{
			{HostDnsTemplate: "bind"},
			{Include: IncludePaths{"missing.yaml"}},
		},
	}
	if err := LoadZoneIncludes(&cfg, dir); err == nil {
		t.Fatal("expected missing file error")
	}
	empty := ConfigRoot{
		Dnsmgr2: ConfigDataGroups{
			{HostDnsTemplate: "bind"},
			{Include: IncludePaths{"", "  "}},
		},
	}
	if err := LoadZoneIncludes(&empty, dir); err == nil {
		t.Fatal("expected empty include path error")
	}
	writeInclude(t, dir, "empty.yaml", "\n")
	ok := ConfigRoot{
		Dnsmgr2: ConfigDataGroups{
			{HostDnsTemplate: "bind"},
			{Include: IncludePaths{"empty.yaml"}},
		},
	}
	if err := LoadZoneIncludes(&ok, dir); err != nil {
		t.Fatal(err)
	}
	if len(ok.Dnsmgr2) != 1 || len(ok.Dnsmgr2[0].Zones) != 0 {
		t.Fatalf("empty file groups = %#v", ok.Dnsmgr2)
	}
}

func TestLoadZoneIncludesYAMLStringAndList(t *testing.T) {
	dir := t.TempDir()
	writeInclude(t, dir, "a.yaml", "zones:\n  - {name: a.example, type: forward, dns_template: default_dns}\n")
	writeInclude(t, dir, "b.yaml", "zones:\n  - {name: b.example, type: forward, dns_template: default_dns}\n")
	main := filepath.Join(dir, "dnsmgr2.yaml")
	body := `
dnsmgr2:
  - host_dns_template: bind
  - include: a.yaml
  - include:
      - b.yaml
`
	if err := os.WriteFile(main, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadConfigFile(main)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Dnsmgr2) != 1 {
		t.Fatalf("groups = %#v", cfg.Dnsmgr2)
	}
	names := []string{}
	for _, z := range cfg.Dnsmgr2[0].Zones {
		names = append(names, z.Name)
	}
	if strings.Join(names, ",") != "a.example,b.example" {
		t.Fatalf("zones = %#v", names)
	}
}

func TestLoadZoneIncludesMustFollowHost(t *testing.T) {
	dir := t.TempDir()
	writeInclude(t, dir, "zones.yaml", "zones:\n  - name: x.example\n    type: forward\n    dns_template: default_dns\n")
	cfg := ConfigRoot{
		Dnsmgr2: ConfigDataGroups{{Include: IncludePaths{"zones.yaml"}}},
	}
	err := LoadZoneIncludes(&cfg, dir)
	if err == nil || !strings.Contains(err.Error(), "must follow") {
		t.Fatalf("error = %v", err)
	}
}

func TestLoadConfigFileResolvesIncludes(t *testing.T) {
	dir := t.TempDir()
	writeInclude(t, dir, "zones.yaml", `
- name: from-include.example
  type: forward
  dns_template: default_dns
`)
	main := filepath.Join(dir, "dnsmgr2.yaml")
	body := `
dbfile: /tmp/dnsmgr2.sqlite
dns:
  host_templates:
    bind:
      type: isc_bind
      configdir: /etc/bind
      includefile: named.conf.dnsmgr2
      zonesdir: /var/lib/bind
      tmpdir: /tmp
dnsmgr2:
  - host_dns_template: bind
  - include: zones.yaml
`
	if err := os.WriteFile(main, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadConfigFile(main)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ConfigDir != dir {
		t.Errorf("ConfigDir = %q", cfg.ConfigDir)
	}
	if len(cfg.Dnsmgr2) != 1 || len(cfg.Dnsmgr2[0].Zones) != 1 || cfg.Dnsmgr2[0].Zones[0].Name != "from-include.example" {
		t.Fatalf("loaded zones = %#v", cfg.Dnsmgr2)
	}
}

func TestLoadZonesUsesIncludes(t *testing.T) {
	dir := t.TempDir()
	writeInclude(t, dir, "zones.yaml", `
zones:
  - name: included.example
    type: forward
    dns_template: default_dns
`)
	dm, err := NewDnsManager(ConfigRoot{
		ConfigDir: dir,
		DNS: ConfigDNS{
			HostTemplates: map[string]ConfigDNS_HostTemplate{
				"bind": {Type: "isc_bind", Configdir: "/etc/bind", IncludeFile: "named.conf.dnsmgr2", ZonesDir: "/var/lib/bind", Tmpdir: "/tmp"},
			},
		},
		Dnsmgr2: ConfigDataGroups{
			{HostDnsTemplate: "bind"},
			{Include: IncludePaths{"zones.yaml"}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := dm.LoadZones(); err != nil {
		t.Fatal(err)
	}
	if len(*dm.ZonesForward) != 1 || (*dm.ZonesForward)[0].Name != "included.example" {
		t.Fatalf("forward zones = %#v", *dm.ZonesForward)
	}
}
