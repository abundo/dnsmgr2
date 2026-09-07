package internal

//
// ISC Kea DHCP driver
//

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"os/exec"
	"sort"
	"strings"
)

type KeaDHCPManagerOpt struct {
	ConfigDHCP *ConfigDHCP
	Host       *ConfigHostDHCPtemplate
	Prefixes   []ConfigPrefix
	Zones      ZonesType
}

type KeaDHCPManager struct {
	P          KeaDHCPManagerOpt
	v4TmpFile  string
	v4DstFile  string
	v6TmpFile  string
	v6DstFile  string
	v4Prefixes []*resolvedPrefix
	v6Prefixes []*resolvedPrefix
}

func NewKeaDHCPManager(p KeaDHCPManagerOpt) *KeaDHCPManager {
	return &KeaDHCPManager{P: p}
}

type keaOptionData struct {
	Name string `json:"name"`
	Data string `json:"data"`
}

type keaPool struct {
	Pool string `json:"pool"`
}

type keaReservation4 struct {
	HWAddress string `json:"hw-address"`
	IPAddress string `json:"ip-address,omitempty"`
	Hostname  string `json:"hostname,omitempty"`
}

type keaReservation6 struct {
	HWAddress   string   `json:"hw-address"`
	IPAddresses []string `json:"ip-addresses,omitempty"`
	Hostname    string   `json:"hostname,omitempty"`
}

type keaSubnet4 struct {
	ID           int               `json:"id"`
	Subnet       string            `json:"subnet"`
	Pools        []keaPool         `json:"pools,omitempty"`
	OptionData   []keaOptionData   `json:"option-data,omitempty"`
	Reservations []keaReservation4 `json:"reservations,omitempty"`
}

type keaSubnet6 struct {
	ID           int               `json:"id"`
	Subnet       string            `json:"subnet"`
	Pools        []keaPool         `json:"pools,omitempty"`
	Reservations []keaReservation6 `json:"reservations,omitempty"`
}

type keaInterfacesConfig struct {
	Interfaces []string `json:"interfaces"`
}

type keaLeaseDatabase struct {
	Type        string `json:"type"`
	Persist     bool   `json:"persist"`
	Name        string `json:"name"`
	LFCInterval int    `json:"lfc-interval"`
}

type keaDhcp4 struct {
	InterfacesConfig keaInterfacesConfig `json:"interfaces-config"`
	LeaseDatabase    keaLeaseDatabase    `json:"lease-database"`
	ValidLifetime    int                 `json:"valid-lifetime"`
	OptionData       []keaOptionData     `json:"option-data,omitempty"`
	Subnet4          []keaSubnet4        `json:"subnet4"`
}

type keaDhcp6 struct {
	InterfacesConfig keaInterfacesConfig `json:"interfaces-config"`
	LeaseDatabase    keaLeaseDatabase    `json:"lease-database"`
	ValidLifetime    int                 `json:"valid-lifetime"`
	OptionData       []keaOptionData     `json:"option-data,omitempty"`
	Subnet6          []keaSubnet6        `json:"subnet6"`
}

type keaConfig4 struct {
	Dhcp4 keaDhcp4 `json:"Dhcp4"`
}

type keaConfig6 struct {
	Dhcp6 keaDhcp6 `json:"Dhcp6"`
}

type keaReservation struct {
	MAC      string
	IP       netip.Addr
	Hostname string
}

func (k *KeaDHCPManager) Restart(proto *ConfigDHCPtemplateProtocol) error {
	slog.Debug("----- KeaDHCPManager.Restart() -----")
	return RunCommand(proto.CmdRestart)
}

func (k *KeaDHCPManager) Status() error {
	slog.Debug("----- KeaDHCPManager.Status() -----")
	fmt.Printf("ISC Kea status: not implemented\n")
	return nil
}

func (k *KeaDHCPManager) Update() error {
	slog.Debug("----- KeaDHCPManager.Update() -----")
	host := k.P.Host
	if host == nil {
		return errors.New("DHCP host template is missing")
	}
	if !host.IPv4.Enable && !host.IPv6.Enable {
		return errors.New("DHCP host template has neither ipv4 nor ipv6 enabled")
	}
	if err := validateDHCPProtocol("ipv4", &host.IPv4); err != nil {
		return err
	}
	if err := validateDHCPProtocol("ipv6", &host.IPv6); err != nil {
		return err
	}

	v4, v6, err := k.resolvePrefixes()
	if err != nil {
		return err
	}
	k.v4Prefixes = v4
	k.v6Prefixes = v6

	reservations, err := k.collectReservations()
	if err != nil {
		return err
	}

	if host.IPv4.Enable {
		k.v4TmpFile = host.IPv4.Tmpdir + "/" + host.IPv4.IncludeFile
		k.v4DstFile = host.IPv4.Configdir + "/" + host.IPv4.IncludeFile
		body, err := k.buildDhcp4(reservations)
		if err != nil {
			return err
		}
		slog.Info("Creating", "kea-dhcp4", k.v4TmpFile)
		if err := writeKeaFile(k.v4TmpFile, "DHCPv4", body); err != nil {
			return err
		}
		if err := keaCheckConfig("kea-dhcp4", k.v4TmpFile); err != nil {
			return err
		}
	}

	if host.IPv6.Enable {
		k.v6TmpFile = host.IPv6.Tmpdir + "/" + host.IPv6.IncludeFile
		k.v6DstFile = host.IPv6.Configdir + "/" + host.IPv6.IncludeFile
		body, err := k.buildDhcp6(reservations)
		if err != nil {
			return err
		}
		slog.Info("Creating", "kea-dhcp6", k.v6TmpFile)
		if err := writeKeaFile(k.v6TmpFile, "DHCPv6", body); err != nil {
			return err
		}
		if err := keaCheckConfig("kea-dhcp6", k.v6TmpFile); err != nil {
			return err
		}
	}

	return nil
}

func (k *KeaDHCPManager) UpdateCommit() error {
	slog.Debug("----- KeaDHCPManager.UpdateCommit() -----")
	host := k.P.Host

	if host.IPv4.Enable {
		if err := k.commitFile(k.v4TmpFile, k.v4DstFile, &host.IPv4); err != nil {
			return err
		}
	}
	if host.IPv6.Enable {
		if err := k.commitFile(k.v6TmpFile, k.v6DstFile, &host.IPv6); err != nil {
			return err
		}
	}
	return nil
}

func (k *KeaDHCPManager) commitFile(tmp, dst string, proto *ConfigDHCPtemplateProtocol) error {
	if Sha256sumEqual(tmp, dst) {
		return nil
	}
	slog.Info("Copy file", "source", tmp, "dest", dst)
	if err := CopyFile(tmp, dst); err != nil {
		return err
	}
	return k.Restart(proto)
}

func (k *KeaDHCPManager) resolvePrefixes() (v4, v6 []*resolvedPrefix, err error) {
	host := k.P.Host
	seen := map[string]bool{}
	for _, cfg := range k.P.Prefixes {
		rp, err := resolvePrefix(cfg)
		if err != nil {
			return nil, nil, err
		}
		key := rp.Prefix.String()
		if seen[key] {
			return nil, nil, fmt.Errorf("duplicate DHCP prefix: %s", key)
		}
		seen[key] = true
		if rp.Prefix.Addr().Is4() {
			if !host.IPv4.Enable {
				return nil, nil, fmt.Errorf("IPv4 DHCP prefix %s but ipv4 is not enabled", key)
			}
			v4 = append(v4, rp)
		} else {
			if !host.IPv6.Enable {
				return nil, nil, fmt.Errorf("IPv6 DHCP prefix %s but ipv6 is not enabled", key)
			}
			v6 = append(v6, rp)
		}
	}
	sort.Slice(v4, func(i, j int) bool { return v4[i].Prefix.String() < v4[j].Prefix.String() })
	sort.Slice(v6, func(i, j int) bool { return v6[i].Prefix.String() < v6[j].Prefix.String() })
	return v4, v6, nil
}

func (k *KeaDHCPManager) collectReservations() ([]keaReservation, error) {
	var out []keaReservation
	seenMAC4 := map[string]string{}
	seenMAC6 := map[string]string{}
	seenIP := map[string]bool{}

	all := append([]*resolvedPrefix{}, k.v4Prefixes...)
	all = append(all, k.v6Prefixes...)

	for _, zone := range k.P.Zones {
		if zone.ConfigZone != nil && zone.ConfigZone.Type != "" && zone.ConfigZone.Type != "forward" {
			continue
		}
		for _, record := range zone.Records {
			if record.MAC == "" {
				continue
			}
			if record.Type != "A" && record.Type != "AAAA" {
				return nil, fmt.Errorf("record %s %s has mac= but is not A/AAAA", record.Name, record.Type)
			}
			ip, err := netip.ParseAddr(record.Value)
			if err != nil {
				return nil, fmt.Errorf("record %s: invalid address %s: %w", record.Name, record.Value, err)
			}
			if record.Type == "A" && !ip.Is4() {
				return nil, fmt.Errorf("record %s: A record is not IPv4", record.Name)
			}
			if record.Type == "AAAA" && !ip.Is6() {
				return nil, fmt.Errorf("record %s: AAAA record is not IPv6", record.Name)
			}
			if findPrefix(all, ip) == nil {
				return nil, fmt.Errorf("record %s (%s) mac=%s does not match any DHCP prefix", record.Name, ip, record.MAC)
			}
			ipStr := ip.String()
			if seenIP[ipStr] {
				return nil, fmt.Errorf("duplicate DHCP reservation IP %s", ipStr)
			}
			seenIP[ipStr] = true
			if ip.Is4() {
				if prev, ok := seenMAC4[record.MAC]; ok {
					return nil, fmt.Errorf("duplicate DHCP reservation MAC %s (IPv4 %s and %s)", record.MAC, prev, ipStr)
				}
				seenMAC4[record.MAC] = ipStr
			} else {
				if prev, ok := seenMAC6[record.MAC]; ok {
					return nil, fmt.Errorf("duplicate DHCP reservation MAC %s (IPv6 %s and %s)", record.MAC, prev, ipStr)
				}
				seenMAC6[record.MAC] = ipStr
			}
			out = append(out, keaReservation{
				MAC:      record.MAC,
				IP:       ip,
				Hostname: recordHostname(zone, record),
			})
		}
	}

	sort.Slice(out, func(i, j int) bool {
		if c := out[i].IP.Compare(out[j].IP); c != 0 {
			return c < 0
		}
		return out[i].MAC < out[j].MAC
	})
	return out, nil
}

func (k *KeaDHCPManager) buildDhcp4(reservations []keaReservation) ([]byte, error) {
	cfg := keaConfig4{
		Dhcp4: keaDhcp4{
			InterfacesConfig: keaInterfacesConfig{Interfaces: []string{"*"}},
			LeaseDatabase: keaLeaseDatabase{
				Type:        "memfile",
				Persist:     true,
				Name:        "/var/lib/kea/kea-leases4.csv",
				LFCInterval: 3600,
			},
			ValidLifetime: 4000,
			OptionData:    k.globalOptionData4(),
			Subnet4:       []keaSubnet4{},
		},
	}

	byPrefix := map[string][]keaReservation4{}
	for _, r := range reservations {
		if !r.IP.Is4() {
			continue
		}
		p := findPrefix(k.v4Prefixes, r.IP)
		if p == nil {
			continue
		}
		key := p.Prefix.String()
		byPrefix[key] = append(byPrefix[key], keaReservation4{
			HWAddress: r.MAC,
			IPAddress: r.IP.String(),
			Hostname:  r.Hostname,
		})
	}

	for i, p := range k.v4Prefixes {
		sub := keaSubnet4{
			ID:     i + 1,
			Subnet: p.Prefix.String(),
		}
		if p.HasRange {
			sub.Pools = []keaPool{{
				Pool: p.RangeStart.String() + " - " + p.RangeEnd.String(),
			}}
		}
		if p.Gateway.IsValid() {
			sub.OptionData = append(sub.OptionData, keaOptionData{
				Name: "routers",
				Data: p.Gateway.String(),
			})
		}
		if p.SubnetMask != "" {
			sub.OptionData = append(sub.OptionData, keaOptionData{
				Name: "subnet-mask",
				Data: p.SubnetMask,
			})
		}
		if res := byPrefix[p.Prefix.String()]; len(res) > 0 {
			sub.Reservations = res
		}
		cfg.Dhcp4.Subnet4 = append(cfg.Dhcp4.Subnet4, sub)
	}

	return json.MarshalIndent(cfg, "", "    ")
}

func (k *KeaDHCPManager) buildDhcp6(reservations []keaReservation) ([]byte, error) {
	cfg := keaConfig6{
		Dhcp6: keaDhcp6{
			InterfacesConfig: keaInterfacesConfig{Interfaces: []string{"*"}},
			LeaseDatabase: keaLeaseDatabase{
				Type:        "memfile",
				Persist:     true,
				Name:        "/var/lib/kea/kea-leases6.csv",
				LFCInterval: 3600,
			},
			ValidLifetime: 4000,
			OptionData:    k.globalOptionData6(),
			Subnet6:       []keaSubnet6{},
		},
	}

	byPrefix := map[string][]keaReservation6{}
	for _, r := range reservations {
		if !r.IP.Is6() {
			continue
		}
		p := findPrefix(k.v6Prefixes, r.IP)
		if p == nil {
			continue
		}
		key := p.Prefix.String()
		byPrefix[key] = append(byPrefix[key], keaReservation6{
			HWAddress:   r.MAC,
			IPAddresses: []string{r.IP.String()},
			Hostname:    r.Hostname,
		})
	}

	for i, p := range k.v6Prefixes {
		sub := keaSubnet6{
			ID:     i + 1,
			Subnet: p.Prefix.String(),
		}
		if p.HasRange {
			sub.Pools = []keaPool{{
				Pool: p.RangeStart.String() + " - " + p.RangeEnd.String(),
			}}
		}
		if res := byPrefix[p.Prefix.String()]; len(res) > 0 {
			sub.Reservations = res
		}
		cfg.Dhcp6.Subnet6 = append(cfg.Dhcp6.Subnet6, sub)
	}

	return json.MarshalIndent(cfg, "", "    ")
}

func (k *KeaDHCPManager) globalOptionData4() []keaOptionData {
	var opts []keaOptionData
	if k.P.ConfigDHCP != nil && len(k.P.ConfigDHCP.DNSServers) > 0 {
		opts = append(opts, keaOptionData{
			Name: "domain-name-servers",
			Data: strings.Join(k.P.ConfigDHCP.DNSServers, ", "),
		})
	}
	if k.P.ConfigDHCP != nil && k.P.ConfigDHCP.DomainName != "" {
		opts = append(opts, keaOptionData{
			Name: "domain-name",
			Data: k.P.ConfigDHCP.DomainName,
		})
	}
	return opts
}

func (k *KeaDHCPManager) globalOptionData6() []keaOptionData {
	var opts []keaOptionData
	if k.P.ConfigDHCP != nil && len(k.P.ConfigDHCP.DNSServers) > 0 {
		opts = append(opts, keaOptionData{
			Name: "dns-servers",
			Data: strings.Join(k.P.ConfigDHCP.DNSServers, ", "),
		})
	}
	if k.P.ConfigDHCP != nil && k.P.ConfigDHCP.DomainName != "" {
		opts = append(opts, keaOptionData{
			Name: "domain-search",
			Data: k.P.ConfigDHCP.DomainName,
		})
	}
	return opts
}

func validateDHCPProtocol(name string, proto *ConfigDHCPtemplateProtocol) error {
	if !proto.Enable {
		return nil
	}
	if proto.Configdir == "" {
		return fmt.Errorf("DHCP %s configdir is empty", name)
	}
	if proto.IncludeFile == "" {
		return fmt.Errorf("DHCP %s includefile is empty", name)
	}
	if proto.Tmpdir == "" {
		return fmt.Errorf("DHCP %s tmpdir is empty", name)
	}
	return nil
}

func writeKeaFile(path, family string, body []byte) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()
	fmt.Fprintf(file, "//------------------------------------------------------------\n")
	fmt.Fprintf(file, "// ISC Kea %s configuration\n", family)
	fmt.Fprintf(file, "// WARNING! do not edit, dnsmgr2 will overwrite your changes\n")
	fmt.Fprintf(file, "//------------------------------------------------------------\n\n")
	if _, err := file.Write(body); err != nil {
		return err
	}
	if len(body) == 0 || body[len(body)-1] != '\n' {
		if _, err := file.Write([]byte("\n")); err != nil {
			return err
		}
	}
	return nil
}

func keaCheckConfig(binary, filename string) error {
	path, err := exec.LookPath(binary)
	if err != nil {
		slog.Debug("kea config check skipped", "binary", binary, "reason", "not on PATH")
		return nil
	}
	cmd := exec.Command(path, "-t", filename)
	out, err := cmd.CombinedOutput()
	output := strings.TrimSpace(string(out))
	if err != nil {
		if output != "" {
			slog.Error(binary+" -t", "file", filename, "err", err, "output", output)
			return fmt.Errorf("%s -t %s: %w\n%s", binary, filename, err, output)
		}
		slog.Error(binary+" -t", "file", filename, "err", err)
		return fmt.Errorf("%s -t %s: %w", binary, filename, err)
	}
	slog.Debug("kea config validation ok", "binary", binary, "file", filename)
	return nil
}
