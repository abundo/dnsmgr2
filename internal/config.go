package internal

// ---------------------------------------------------------------------------
//   Source
// ---------------------------------------------------------------------------

type ConfigSource struct {
	Type string
	Name string
}

type ConfigSources []ConfigSource

// ---------------------------------------------------------------------------
//   Destination
// ---------------------------------------------------------------------------

type ConfigDestination struct {
	Type string
	Name string
}
type ConfigDestinations []ConfigDestination

// ---------------------------------------------------------------------------
//   DHCP
// ---------------------------------------------------------------------------

type ConfigDHCPtemplateProtocol struct {
	Enable      bool
	Configdir   string
	IncludeFile string `yaml:"includefile"`
	Tmpdir      string
	CmdRestart  string `yaml:"cmd_restart"`
}

type ConfigHostDHCPtemplate struct {
	Type string
	IPv4 ConfigDHCPtemplateProtocol `yaml:"ipv4"`
	IPv6 ConfigDHCPtemplateProtocol `yaml:"ipv6"`
}

type ConfigDHCP struct {
	DomainName    string                            `yaml:"domain_name"`
	DNSServers    []string                          `yaml:"dns_servers"`
	HostTemplates map[string]ConfigHostDHCPtemplate `yaml:"host_templates"`
}

// ConfigPrefix is a DHCP subnet. Name is a CIDR prefix (192.168.1.0/24).
// Range is an optional pool (192.168.1.100-192.168.1.200). Gateway defaults
// to the first usable address in the prefix. SubnetMask defaults to the
// mask implied by the prefix length (IPv4 only).
type ConfigPrefix struct {
	Name       string
	Range      string
	Gateway    string
	SubnetMask string `yaml:"subnet_mask"`
}

// ---------------------------------------------------------------------------
//	DNS
// ---------------------------------------------------------------------------

// dns->host_template:
type ConfigDNS_HostTemplate struct {
	Type          string
	Configdir     string
	IncludeFile   string
	ZonesDir      string
	Zonesfile     string
	Tmpdir        string
	CmdReloadAll  string `yaml:"cmd_reload_all"`
	CmdReloadZone string `yaml:"cmd_reload_zone"`
	CmdRestart    string `yaml:"cmd_restart"`
}

// dns->soa_templates:
type ConfigDNS_SOA_template struct {
	Mname        string
	Rname        string
	SerialFormat string
	Refresh      int
	Retry        int
	Expire       int
	Minimum      int
}

// dns->zone_templates:
type ConfigDNS_TemplateNS struct {
	Name  string
	TTL   string
	Type  string
	Value string
}

type ConfigDNS_ZoneTemplate struct {
	SOA            string
	DefaultTTL     string `yaml:"default_ttl"`
	NS             []ConfigDNS_TemplateNS
	AllowUpdate    []string
	DNSSECpolicy   string `yaml:"dnssec_policy"`
	ParentalAgents []string
	ZoneOptions    []string
}

type ConfigDNS struct {
	HostTemplates map[string]ConfigDNS_HostTemplate `yaml:"host_templates"`
	SOATemplates  map[string]ConfigDNS_SOA_template `yaml:"soa_templates"`
	ZoneTemplates map[string]ConfigDNS_ZoneTemplate `yaml:"zone_templates"`
}

// ---------------------------------------------------------------------------
//	DNS
// ---------------------------------------------------------------------------

type ConfigZone struct {
	Name        string
	Type        string // forward, reverse4, reverse6
	DnsTemplate string `yaml:"dns_template"`
}

type ConfigDataType struct {
	HostDnsTemplate  string `yaml:"host_dns_template"`
	HostDhcpTemplate string `yaml:"host_dhcp_template"`
	Prefixes         []ConfigPrefix
	Zones            []ConfigZone
}

type ConfigDataGroups []ConfigDataType

type ConfigRoot struct {
	Dbfile       string `yaml:"dbfile"`
	Sources      ConfigSources
	Destinations ConfigDestinations
	DHCP         ConfigDHCP
	DNS          ConfigDNS

	Dnsmgr2 ConfigDataGroups
}

var Config ConfigRoot
