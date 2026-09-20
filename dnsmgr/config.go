package dnsmgr

import "strings"

// ---------------------------------------------------------------------------
//   Source
// ---------------------------------------------------------------------------

// ConfigSource is a records input. Type is "file" (text) or "json".
type ConfigSource struct {
	Type string
	Name string
}

type ConfigSources []ConfigSource

// ---------------------------------------------------------------------------
//   Destination
// ---------------------------------------------------------------------------

// ConfigDestination is accepted in YAML for compatibility and ignored.
// Drivers are selected by host_dns_template / host_dhcp_template.
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
	CmdStatus   string `yaml:"cmd_status"`
}

type ConfigHostDHCPtemplate struct {
	Type string
	IPv4 ConfigDHCPtemplateProtocol `yaml:"ipv4"`
	IPv6 ConfigDHCPtemplateProtocol `yaml:"ipv6"`
}

type ConfigDHCP struct {
	DomainName    string                            `yaml:"domain_name" optional:"true"`
	DNSServers    []string                          `yaml:"dns_servers" optional:"true"`
	HostTemplates map[string]ConfigHostDHCPtemplate `yaml:"host_templates"`
}

// ConfigPrefix is a DHCP subnet. Name is a CIDR prefix (192.168.1.0/24).
// Range is an optional pool (192.168.1.100-192.168.1.200). Gateway defaults
// to the first usable address in the prefix. SubnetMask defaults to the
// mask implied by the prefix length (IPv4 only). DNSServers, when set,
// override dhcp.dns_servers for this subnet only.
type ConfigPrefix struct {
	Name       string
	Range      string
	Gateway    string
	SubnetMask string   `yaml:"subnet_mask"`
	DNSServers []string `yaml:"dns_servers" optional:"true"`
}

// ---------------------------------------------------------------------------
//	DNS
// ---------------------------------------------------------------------------

// dns->host_template:
type ConfigDNS_HostTemplate struct {
	Type          string
	Configdir     string
	IncludeFile   string `yaml:"includefile"`
	ZonesDir      string `yaml:"zonesdir"`
	Zonesfile     string
	Tmpdir        string
	CmdReloadAll  string `yaml:"cmd_reload_all"`
	CmdReloadZone string `yaml:"cmd_reload_zone"`
	CmdRestart    string `yaml:"cmd_restart"`
	CmdStatus     string `yaml:"cmd_status"`
}

// dns->soa_templates:
type ConfigDNS_SOA_template struct {
	Mname        string
	Rname        string
	SerialFormat string `yaml:"serial_format"`
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
	AllowUpdate    []string `yaml:"allow_update"`
	DNSSECpolicy   string   `yaml:"dnssec_policy"`
	ParentalAgents []string `yaml:"parental_agents"`
	ZoneOptions    []string `yaml:"zone_options"`
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

// IncludePaths is one path or a YAML list of paths.
type IncludePaths []string

func (p *IncludePaths) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var one string
	if err := unmarshal(&one); err == nil {
		one = strings.TrimSpace(one)
		if one == "" {
			*p = nil
			return nil
		}
		*p = IncludePaths{one}
		return nil
	}
	var many []string
	if err := unmarshal(&many); err != nil {
		return err
	}
	*p = many
	return nil
}

type ConfigDataType struct {
	HostDnsTemplate  string `yaml:"host_dns_template"`
	HostDhcpTemplate string `yaml:"host_dhcp_template"`
	// Include is a separate dnsmgr2 list item (not a field of
	// host_dns_template). A string or a list of YAML files; loaded zones
	// and prefixes are appended to the preceding list item. Paths are
	// relative to the main config file's directory unless they are
	// absolute.
	Include  IncludePaths `yaml:"include,omitempty"`
	Prefixes []ConfigPrefix
	Zones    []ConfigZone
}

type ConfigDataGroups []ConfigDataType

type ConfigRoot struct {
	Dbfile       string `yaml:"dbfile"`
	Sources      ConfigSources
	Destinations ConfigDestinations
	DHCP         ConfigDHCP
	DNS          ConfigDNS

	Dnsmgr2 ConfigDataGroups

	// ConfigDir is the directory of the main YAML file. Relative include
	// paths are resolved against it. Not read from YAML.
	ConfigDir string `yaml:"-" boa:"ignore"`
}
