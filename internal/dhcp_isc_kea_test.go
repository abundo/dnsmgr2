package internal

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func testKeaHost(dir string) *ConfigHostDHCPtemplate {
	return &ConfigHostDHCPtemplate{
		Type: "isc_kea",
		IPv4: ConfigDHCPtemplateProtocol{
			Enable:      true,
			Configdir:   dir,
			IncludeFile: "kea-dhcp4.dnsmgr2.json",
			Tmpdir:      dir,
			CmdRestart:  "true",
		},
	}
}

func readKeaJSONArray[T any](t *testing.T, path string) T {
	t.Helper()
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text := string(body)
	if !strings.Contains(text, "WARNING! do not edit") {
		t.Error("missing overwrite warning")
	}
	if strings.Contains(text, `"Dhcp4"`) || strings.Contains(text, `"Dhcp6"`) ||
		strings.Contains(text, "interfaces-config") || strings.Contains(text, "lease-database") {
		t.Errorf("include file looks like a full Kea config:\n%s", text)
	}
	jsonStart := strings.Index(text, "[")
	if jsonStart < 0 {
		t.Fatalf("no JSON array in %s:\n%s", path, text)
	}
	var v T
	if err := json.Unmarshal([]byte(text[jsonStart:]), &v); err != nil {
		t.Fatalf("unmarshal: %v\n%s", err, text)
	}
	return v
}

func TestKeaBuildDhcp4ReservationAndDefaults(t *testing.T) {
	dir := t.TempDir()
	dm := testDnsManager("example.com")
	zone := (*dm.Zones)[0]
	zone.ConfigZone = &ConfigZone{Name: "example.com", Type: "forward"}
	zone.Records = RecordsType{
		{Name: "test", Type: "A", Value: "192.0.2.4", MAC: "aa:bb:cc:dd:ee:ff"},
		{Name: "mail", Type: "A", Value: "192.0.2.10"},
	}

	k := NewKeaDHCPManager(KeaDHCPManagerOpt{
		ConfigDHCP: &ConfigDHCP{
			DomainName: "example.com",
			DNSServers: []string{"192.0.2.53", "192.0.2.54"},
		},
		Host: testKeaHost(dir),
		Prefixes: []ConfigPrefix{
			{Name: "192.0.2.0/24", Range: "192.0.2.100-192.0.2.200"},
		},
		Zones: *dm.Zones,
	})
	if err := k.Update(); err != nil {
		t.Fatalf("Update: %v", err)
	}

	subnets := readKeaJSONArray[[]keaSubnet4](t, filepath.Join(dir, "kea-dhcp4.dnsmgr2.json"))
	if len(subnets) != 1 {
		t.Fatalf("subnets = %d", len(subnets))
	}
	sub := subnets[0]
	if sub.ID != 1 || sub.Subnet != "192.0.2.0/24" {
		t.Errorf("subnet = %#v", sub)
	}
	if len(sub.Pools) != 1 || sub.Pools[0].Pool != "192.0.2.100 - 192.0.2.200" {
		t.Errorf("pools = %#v", sub.Pools)
	}
	gotOpts := map[string]string{}
	for _, o := range sub.OptionData {
		gotOpts[o.Name] = o.Data
	}
	if gotOpts["routers"] != "192.0.2.1" {
		t.Errorf("routers = %q", gotOpts["routers"])
	}
	if gotOpts["subnet-mask"] != "255.255.255.0" {
		t.Errorf("subnet-mask = %q", gotOpts["subnet-mask"])
	}
	if gotOpts["domain-name-servers"] != "192.0.2.53, 192.0.2.54" {
		t.Errorf("dns option = %q", gotOpts["domain-name-servers"])
	}
	if gotOpts["domain-name"] != "example.com" {
		t.Errorf("domain option = %q", gotOpts["domain-name"])
	}
	if len(sub.Reservations) != 1 {
		t.Fatalf("reservations = %#v", sub.Reservations)
	}
	res := sub.Reservations[0]
	if res.HWAddress != "aa:bb:cc:dd:ee:ff" || res.IPAddress != "192.0.2.4" || res.Hostname != "test.example.com" {
		t.Errorf("reservation = %#v", res)
	}
}

func TestKeaPrefixDNSServersOverride(t *testing.T) {
	dir := t.TempDir()
	k := NewKeaDHCPManager(KeaDHCPManagerOpt{
		ConfigDHCP: &ConfigDHCP{
			DomainName: "example.com",
			DNSServers: []string{"192.0.2.53"},
		},
		Host: testKeaHost(dir),
		Prefixes: []ConfigPrefix{
			{Name: "192.0.2.0/24", DNSServers: []string{"198.51.100.53"}},
		},
	})
	if err := k.Update(); err != nil {
		t.Fatalf("Update: %v", err)
	}
	subnets := readKeaJSONArray[[]keaSubnet4](t, filepath.Join(dir, "kea-dhcp4.dnsmgr2.json"))
	got := map[string]string{}
	for _, o := range subnets[0].OptionData {
		got[o.Name] = o.Data
	}
	if got["domain-name-servers"] != "198.51.100.53" {
		t.Errorf("prefix dns = %#v", got)
	}
	if got["domain-name"] != "example.com" {
		t.Errorf("domain-name = %q", got["domain-name"])
	}
}

func TestKeaReservationIPOutsidePrefix(t *testing.T) {
	dir := t.TempDir()
	dm := testDnsManager("example.com")
	(*dm.Zones)[0].Records = RecordsType{
		{Name: "test", Type: "A", Value: "10.0.0.4", MAC: "aa:bb:cc:dd:ee:ff"},
	}
	k := NewKeaDHCPManager(KeaDHCPManagerOpt{
		ConfigDHCP: &ConfigDHCP{},
		Host:       testKeaHost(dir),
		Prefixes:   []ConfigPrefix{{Name: "192.0.2.0/24"}},
		Zones:      *dm.Zones,
	})
	err := k.Update()
	if err == nil || !strings.Contains(err.Error(), "does not match any DHCP prefix") {
		t.Fatalf("Update = %v, want prefix mismatch", err)
	}
}

func TestKeaDuplicateMAC(t *testing.T) {
	dir := t.TempDir()
	dm := testDnsManager("example.com")
	(*dm.Zones)[0].Records = RecordsType{
		{Name: "a", Type: "A", Value: "192.0.2.4", MAC: "aa:bb:cc:dd:ee:ff"},
		{Name: "b", Type: "A", Value: "192.0.2.5", MAC: "aa:bb:cc:dd:ee:ff"},
	}
	k := NewKeaDHCPManager(KeaDHCPManagerOpt{
		ConfigDHCP: &ConfigDHCP{},
		Host:       testKeaHost(dir),
		Prefixes:   []ConfigPrefix{{Name: "192.0.2.0/24"}},
		Zones:      *dm.Zones,
	})
	err := k.Update()
	if err == nil || !strings.Contains(err.Error(), "duplicate DHCP reservation MAC") {
		t.Fatalf("Update = %v, want duplicate MAC", err)
	}
}

func TestKeaUpdateCommitUnchangedSkipsRestart(t *testing.T) {
	dir := t.TempDir()
	tmp := filepath.Join(dir, "tmp")
	dst := filepath.Join(dir, "dst")
	if err := os.Mkdir(tmp, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(dst, 0o755); err != nil {
		t.Fatal(err)
	}
	host := testKeaHost(dir)
	host.IPv4.Tmpdir = tmp
	host.IPv4.Configdir = dst
	host.IPv4.CmdRestart = "true"
	dm := testDnsManager("example.com")
	(*dm.Zones)[0].Records = RecordsType{
		{Name: "test", Type: "A", Value: "192.0.2.4", MAC: "aa:bb:cc:dd:ee:ff"},
	}
	k := NewKeaDHCPManager(KeaDHCPManagerOpt{
		ConfigDHCP: &ConfigDHCP{DomainName: "example.com"},
		Host:       host,
		Prefixes:   []ConfigPrefix{{Name: "192.0.2.0/24"}},
		Zones:      *dm.Zones,
	})
	if err := k.Update(); err != nil {
		t.Fatalf("Update: %v", err)
	}
	if err := k.UpdateCommit(); err != nil {
		t.Fatalf("first UpdateCommit: %v", err)
	}
	host.IPv4.CmdRestart = "false"
	if err := k.Update(); err != nil {
		t.Fatalf("second Update: %v", err)
	}
	if err := k.UpdateCommit(); err != nil {
		t.Fatalf("second UpdateCommit: %v", err)
	}
}

func TestKeaDhcp6Reservation(t *testing.T) {
	dir := t.TempDir()
	dm := testDnsManager("example.com")
	(*dm.Zones)[0].Records = RecordsType{
		{Name: "test", Type: "AAAA", Value: "2001:db8::10", MAC: "aa:bb:cc:dd:ee:ff"},
	}
	k := NewKeaDHCPManager(KeaDHCPManagerOpt{
		ConfigDHCP: &ConfigDHCP{
			DomainName: "example.com",
			DNSServers: []string{"2001:db8::53"},
		},
		Host: &ConfigHostDHCPtemplate{
			Type: "isc_kea",
			IPv6: ConfigDHCPtemplateProtocol{
				Enable:      true,
				Configdir:   dir,
				IncludeFile: "kea-dhcp6.dnsmgr2.json",
				Tmpdir:      dir,
				CmdRestart:  "true",
			},
		},
		Prefixes: []ConfigPrefix{
			{Name: "2001:db8::/64", Range: "2001:db8::100-2001:db8::200"},
		},
		Zones: *dm.Zones,
	})
	if err := k.Update(); err != nil {
		t.Fatalf("Update: %v", err)
	}
	subnets := readKeaJSONArray[[]keaSubnet6](t, filepath.Join(dir, "kea-dhcp6.dnsmgr2.json"))
	if len(subnets) != 1 {
		t.Fatalf("subnets = %d", len(subnets))
	}
	sub := subnets[0]
	if sub.Subnet != "2001:db8::/64" {
		t.Errorf("subnet = %s", sub.Subnet)
	}
	if len(sub.Pools) != 1 || sub.Pools[0].Pool != "2001:db8::100 - 2001:db8::200" {
		t.Errorf("pools = %#v", sub.Pools)
	}
	gotOpts := map[string]string{}
	for _, o := range sub.OptionData {
		gotOpts[o.Name] = o.Data
	}
	if gotOpts["dns-servers"] != "2001:db8::53" {
		t.Errorf("dns-servers = %q", gotOpts["dns-servers"])
	}
	if gotOpts["domain-search"] != "example.com" {
		t.Errorf("domain-search = %q", gotOpts["domain-search"])
	}
	if len(sub.Reservations) != 1 {
		t.Fatalf("reservations = %#v", sub.Reservations)
	}
	res := sub.Reservations[0]
	if res.HWAddress != "aa:bb:cc:dd:ee:ff" || len(res.IPAddresses) != 1 || res.IPAddresses[0] != "2001:db8::10" {
		t.Errorf("reservation = %#v", res)
	}
	if res.Hostname != "test.example.com" {
		t.Errorf("hostname = %s", res.Hostname)
	}
}

func TestKeaSyncFromDnsManager(t *testing.T) {
	dir := t.TempDir()
	dm, err := NewDnsManager(ConfigRoot{
		DHCP: ConfigDHCP{
			DomainName: "example.com",
			DNSServers: []string{"192.0.2.53"},
			HostTemplates: map[string]ConfigHostDHCPtemplate{
				"isc_kea": {
					Type: "isc_kea",
					IPv4: ConfigDHCPtemplateProtocol{
						Enable:      true,
						Configdir:   dir,
						IncludeFile: "kea-dhcp4.dnsmgr2.json",
						Tmpdir:      dir,
						CmdRestart:  "true",
					},
				},
			},
		},
		Dnsmgr2: ConfigDataGroups{
			{
				HostDhcpTemplate: "isc_kea",
				Prefixes:         []ConfigPrefix{{Name: "192.0.2.0/24", Range: "192.0.2.100-192.0.2.200"}},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	z := &Zone{Name: "example.com", ConfigZone: &ConfigZone{Name: "example.com", Type: "forward"}}
	z.Records = RecordsType{
		{Name: "host1", Type: "A", Value: "192.0.2.4", MAC: "02:00:00:00:00:01"},
	}
	*dm.Zones = append(*dm.Zones, z)
	*dm.ZonesForward = append(*dm.ZonesForward, z)

	if err := dm.Sync(); err != nil {
		t.Fatalf("Sync: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "kea-dhcp4.dnsmgr2.json")); err != nil {
		t.Fatalf("kea include not written: %v", err)
	}
}

func TestKeaMACOnNonAddressRecord(t *testing.T) {
	dir := t.TempDir()
	dm := testDnsManager("example.com")
	(*dm.Zones)[0].Records = RecordsType{
		{Name: "@", Type: "MX", Value: "10 mail", MAC: "aa:bb:cc:dd:ee:ff"},
	}
	k := NewKeaDHCPManager(KeaDHCPManagerOpt{
		ConfigDHCP: &ConfigDHCP{},
		Host:       testKeaHost(dir),
		Prefixes:   []ConfigPrefix{{Name: "192.0.2.0/24"}},
		Zones:      *dm.Zones,
	})
	err := k.Update()
	if err == nil || !strings.Contains(err.Error(), "not A/AAAA") {
		t.Fatalf("Update = %v, want A/AAAA error", err)
	}
}

func TestKeaEmptyPrefixesWritesArray(t *testing.T) {
	dir := t.TempDir()
	k := NewKeaDHCPManager(KeaDHCPManagerOpt{
		ConfigDHCP: &ConfigDHCP{},
		Host:       testKeaHost(dir),
	})
	if err := k.Update(); err != nil {
		t.Fatalf("Update: %v", err)
	}
	subnets := readKeaJSONArray[[]keaSubnet4](t, filepath.Join(dir, "kea-dhcp4.dnsmgr2.json"))
	if subnets == nil {
		t.Fatal("subnets is JSON null, want []")
	}
	if len(subnets) != 0 {
		t.Errorf("subnets = %#v, want empty", subnets)
	}
}

func TestKeaValidationStub(t *testing.T) {
	stub, err := keaValidationStub("Dhcp4", "subnet4", "/etc/kea/kea-dhcp4.dnsmgr2.json")
	if err != nil {
		t.Fatal(err)
	}
	text := string(stub)
	for _, want := range []string{
		`"Dhcp4"`,
		`"subnet4": <?include "/etc/kea/kea-dhcp4.dnsmgr2.json"?>`,
		`"interfaces-config"`,
		`kea-leases4.csv`,
	} {
		if !strings.Contains(text, want) {
			t.Errorf("stub missing %q\n%s", want, text)
		}
	}

	stub6, err := keaValidationStub("Dhcp6", "subnet6", `/tmp/path with "quote".json`)
	if err != nil {
		t.Fatal(err)
	}
	text6 := string(stub6)
	if !strings.Contains(text6, `"Dhcp6"`) || !strings.Contains(text6, `"subnet6": <?include`) {
		t.Errorf("v6 stub = %s", text6)
	}
	if !strings.Contains(text6, `kea-leases6.csv`) {
		t.Errorf("v6 stub missing leases6:\n%s", text6)
	}
	if !strings.Contains(text6, `\u0022`) && !strings.Contains(text6, `\"`) {
		t.Errorf("quoted path not escaped:\n%s", text6)
	}
}

func TestExampleYAMLHasKeaConfig(t *testing.T) {
	var cfg ConfigRoot
	if err := ReadConfigFile("../examples/dnsmgr2-example.yaml", &cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.DHCP.DomainName != "example.com" {
		t.Errorf("domain_name = %q", cfg.DHCP.DomainName)
	}
	if len(cfg.DHCP.DNSServers) != 2 {
		t.Errorf("dns_servers = %#v", cfg.DHCP.DNSServers)
	}
	host, ok := cfg.DHCP.HostTemplates["isc_kea"]
	if !ok || host.Type != "isc_kea" || !host.IPv4.Enable {
		t.Errorf("host template = %#v", host)
	}
	if host.IPv4.IncludeFile != "kea-dhcp4.dnsmgr2.json" {
		t.Errorf("ipv4 includefile = %q", host.IPv4.IncludeFile)
	}
	if host.IPv6.IncludeFile != "kea-dhcp6.dnsmgr2.json" {
		t.Errorf("ipv6 includefile = %q", host.IPv6.IncludeFile)
	}
	if len(cfg.Dnsmgr2) != 1 || cfg.Dnsmgr2[0].HostDhcpTemplate != "isc_kea" {
		t.Errorf("dnsmgr2 = %#v", cfg.Dnsmgr2)
	}
	if len(cfg.Dnsmgr2[0].Prefixes) != 1 || cfg.Dnsmgr2[0].Prefixes[0].Name != "192.0.2.0/24" {
		t.Errorf("prefixes = %#v", cfg.Dnsmgr2[0].Prefixes)
	}
}

func TestLoadZonesUnknownDHCPTemplate(t *testing.T) {
	dm, err := NewDnsManager(ConfigRoot{
		Dnsmgr2: ConfigDataGroups{
			{HostDhcpTemplate: "missing", Prefixes: []ConfigPrefix{{Name: "192.0.2.0/24"}}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	err = dm.LoadZones()
	if err == nil || !strings.Contains(err.Error(), "unknown Host DHCP template") {
		t.Fatalf("LoadZones = %v", err)
	}
}
