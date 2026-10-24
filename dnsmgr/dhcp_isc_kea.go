package dnsmgr

//
// ISC Kea DHCP driver
//
// Writes a JSON array of subnets (pools, per-subnet options, reservations)
// to the host template includefile. The operator's main Kea config must
// include that file as the subnet4 / subnet6 value:
//
//	"subnet4": <?include "/etc/kea/kea-dhcp4.dnsmgr2.json"?>
//

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
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
	OptionData   []keaOptionData   `json:"option-data,omitempty"`
	Reservations []keaReservation6 `json:"reservations,omitempty"`
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

func (k *KeaDHCPManager) Status(proto *ConfigDHCPtemplateProtocol, family string) error {
	slog.Debug("----- KeaDHCPManager.Status() -----", "family", family)
	if proto.CmdStatus != "" {
		return RunCommand(proto.CmdStatus)
	}
	dst, err := SafeJoin(proto.Configdir, proto.IncludeFile)
	if err != nil {
		return err
	}
	if _, err := os.Stat(dst); err != nil {
		fmt.Printf("ISC Kea %s include %s: missing\n", family, dst)
	} else {
		fmt.Printf("ISC Kea %s include %s: present\n", family, dst)
	}
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
		k.v4TmpFile, err = SafeJoin(host.IPv4.Tmpdir, host.IPv4.IncludeFile)
		if err != nil {
			return err
		}
		k.v4DstFile, err = SafeJoin(host.IPv4.Configdir, host.IPv4.IncludeFile)
		if err != nil {
			return err
		}
		body, err := k.buildDhcp4(reservations)
		if err != nil {
			return err
		}
		slog.Info("Creating", "kea-dhcp4", k.v4TmpFile)
		if err := writeKeaFile(k.v4TmpFile, "DHCPv4", body); err != nil {
			return err
		}
		if err := keaCheckConfig("kea-dhcp4", k.v4TmpFile, host.IPv4.Configdir, "Dhcp4", "subnet4"); err != nil {
			return err
		}
	}

	if host.IPv6.Enable {
		k.v6TmpFile, err = SafeJoin(host.IPv6.Tmpdir, host.IPv6.IncludeFile)
		if err != nil {
			return err
		}
		k.v6DstFile, err = SafeJoin(host.IPv6.Configdir, host.IPv6.IncludeFile)
		if err != nil {
			return err
		}
		body, err := k.buildDhcp6(reservations)
		if err != nil {
			return err
		}
		slog.Info("Creating", "kea-dhcp6", k.v6TmpFile)
		if err := writeKeaFile(k.v6TmpFile, "DHCPv6", body); err != nil {
			return err
		}
		if err := keaCheckConfig("kea-dhcp6", k.v6TmpFile, host.IPv6.Configdir, "Dhcp6", "subnet6"); err != nil {
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
	equal, err := FilesEqual(tmp, dst)
	if err != nil {
		return err
	}
	if equal {
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

	subnets := make([]keaSubnet4, 0, len(k.v4Prefixes))
	for i, p := range k.v4Prefixes {
		sub := keaSubnet4{
			ID:         i + 1,
			Subnet:     p.Prefix.String(),
			OptionData: k.subnetOptionData4(p),
		}
		if p.HasRange {
			sub.Pools = []keaPool{{
				Pool: p.RangeStart.String() + " - " + p.RangeEnd.String(),
			}}
		}
		if res := byPrefix[p.Prefix.String()]; len(res) > 0 {
			sub.Reservations = res
		}
		subnets = append(subnets, sub)
	}

	return json.MarshalIndent(subnets, "", "    ")
}

func (k *KeaDHCPManager) buildDhcp6(reservations []keaReservation) ([]byte, error) {
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

	subnets := make([]keaSubnet6, 0, len(k.v6Prefixes))
	for i, p := range k.v6Prefixes {
		sub := keaSubnet6{
			ID:         i + 1,
			Subnet:     p.Prefix.String(),
			OptionData: k.subnetOptionData6(p),
		}
		if p.HasRange {
			sub.Pools = []keaPool{{
				Pool: p.RangeStart.String() + " - " + p.RangeEnd.String(),
			}}
		}
		if res := byPrefix[p.Prefix.String()]; len(res) > 0 {
			sub.Reservations = res
		}
		subnets = append(subnets, sub)
	}

	return json.MarshalIndent(subnets, "", "    ")
}

func (k *KeaDHCPManager) subnetOptionData4(p *resolvedPrefix) []keaOptionData {
	var opts []keaOptionData
	if p.Gateway.IsValid() {
		opts = append(opts, keaOptionData{
			Name: "routers",
			Data: p.Gateway.String(),
		})
	}
	if p.SubnetMask != "" {
		opts = append(opts, keaOptionData{
			Name: "subnet-mask",
			Data: p.SubnetMask,
		})
	}
	dns := p.DNSServers
	if len(dns) == 0 && k.P.ConfigDHCP != nil {
		dns = k.P.ConfigDHCP.DNSServers
	}
	if len(dns) > 0 {
		opts = append(opts, keaOptionData{
			Name: "domain-name-servers",
			Data: strings.Join(dns, ", "),
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

func (k *KeaDHCPManager) subnetOptionData6(p *resolvedPrefix) []keaOptionData {
	var opts []keaOptionData
	dns := p.DNSServers
	if len(dns) == 0 && k.P.ConfigDHCP != nil {
		dns = k.P.ConfigDHCP.DNSServers
	}
	if len(dns) > 0 {
		opts = append(opts, keaOptionData{
			Name: "dns-servers",
			Data: strings.Join(dns, ", "),
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
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()
	fmt.Fprintf(file, "//------------------------------------------------------------\n")
	fmt.Fprintf(file, "// ISC Kea %s subnet include\n", family)
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

func keaValidationStub(dhcpKey, subnetKey, includePath string) ([]byte, error) {
	dhcpJSON, err := json.Marshal(dhcpKey)
	if err != nil {
		return nil, err
	}
	subnetJSON, err := json.Marshal(subnetKey)
	if err != nil {
		return nil, err
	}
	includeJSON, err := json.Marshal(includePath)
	if err != nil {
		return nil, err
	}
	lease := "/tmp/dnsmgr2-kea-leases4.csv"
	if dhcpKey == "Dhcp6" {
		lease = "/tmp/dnsmgr2-kea-leases6.csv"
	}
	leaseJSON, err := json.Marshal(lease)
	if err != nil {
		return nil, err
	}
	var b strings.Builder
	fmt.Fprintf(&b, "{\n")
	fmt.Fprintf(&b, "    %s: {\n", dhcpJSON)
	fmt.Fprintf(&b, "        \"interfaces-config\": { \"interfaces\": [ \"*\" ] },\n")
	// persist false so -t does not open a lease file. Packaged kea-dhcp4
	// is AppArmor-confined and may not write an arbitrary path.
	fmt.Fprintf(&b, "        \"lease-database\": { \"type\": \"memfile\", \"persist\": false, \"name\": %s },\n", leaseJSON)
	fmt.Fprintf(&b, "        \"valid-lifetime\": 4000,\n")
	fmt.Fprintf(&b, "        %s: <?include %s?>\n", subnetJSON, includeJSON)
	fmt.Fprintf(&b, "    }\n")
	fmt.Fprintf(&b, "}\n")
	return []byte(b.String()), nil
}

func keaCheckConfig(binary, includePath, configDir, dhcpKey, subnetKey string) error {
	path, err := exec.LookPath(binary)
	if err != nil {
		slog.Warn("kea config check skipped; binary not on PATH, generated config not validated", "binary", binary)
		return nil
	}
	stubPath, cleanup, err := prepareKeaSyntaxCheck(configDir, includePath, dhcpKey, subnetKey)
	if err != nil {
		return err
	}
	defer cleanup()

	cmd := exec.Command(path, "-t", stubPath)
	cred, err := keaSyntaxCheckCredential(configDir)
	if err != nil {
		return err
	}
	if cred != nil {
		slog.Debug("kea config check running as configdir owner", "binary", binary, "uid", cred.Uid, "gid", cred.Gid)
		cmd.SysProcAttr = &syscall.SysProcAttr{Credential: cred}
	}
	out, err := cmd.CombinedOutput()
	output := strings.TrimSpace(string(out))
	if err != nil {
		if output != "" {
			slog.Error(binary+" -t", "file", stubPath, "err", err, "output", output)
			msg := fmt.Sprintf("%s -t %s: %v\n%s", binary, stubPath, err, output)
			if strings.Contains(output, "Unable to open file") {
				msg += "\nKea could not read the check file. Debian and Ubuntu AppArmor only allow kea-dhcp4/kea-dhcp6 to read /etc/kea, and that directory is often mode 0750 owned by _kea."
			}
			return errors.New(msg)
		}
		slog.Error(binary+" -t", "file", stubPath, "err", err)
		return fmt.Errorf("%s -t %s: %w", binary, stubPath, err)
	}
	slog.Debug("kea config validation ok", "binary", binary, "file", includePath)
	return nil
}

// prepareKeaSyntaxCheck copies the generated include into configDir and
// writes a stub next to it. Packaged Kea is confined to /etc/kea, so a
// stub under tmpdir (often /var/lib/dnsmgr2) fails -t with "Unable to
// open file" even when the file exists and is mode 0644.
func prepareKeaSyntaxCheck(configDir, includePath, dhcpKey, subnetKey string) (stubPath string, cleanup func(), err error) {
	cleanup = func() {}
	absInclude, err := filepath.Abs(includePath)
	if err != nil {
		return "", cleanup, err
	}
	base := filepath.Base(absInclude)
	includeCopy := filepath.Join(configDir, "dnsmgr2-syntax-"+base)
	stubPath = filepath.Join(configDir, "dnsmgr2-syntax-"+base+".conf")

	body, err := os.ReadFile(absInclude)
	if err != nil {
		return "", cleanup, err
	}
	var written []string
	cleanup = func() {
		for _, p := range written {
			os.Remove(p)
		}
	}
	if err := writeKeaCheckFile(includeCopy, body); err != nil {
		return "", cleanup, err
	}
	written = append(written, includeCopy)

	absCopy, err := filepath.Abs(includeCopy)
	if err != nil {
		cleanup()
		return "", func() {}, err
	}
	stub, err := keaValidationStub(dhcpKey, subnetKey, absCopy)
	if err != nil {
		cleanup()
		return "", func() {}, err
	}
	if err := writeKeaCheckFile(stubPath, stub); err != nil {
		cleanup()
		return "", func() {}, err
	}
	written = append(written, stubPath)
	return stubPath, cleanup, nil
}

func writeKeaCheckFile(path string, body []byte) error {
	// WriteFile applies umask. chmod afterwards so _kea can read the
	// file when root's umask is 0077 and /etc/kea is mode 0750.
	if err := os.WriteFile(path, body, 0o644); err != nil {
		return err
	}
	return os.Chmod(path, 0o644)
}

// keaSyntaxCheckCredential returns a credential for the config directory
// owner when the current user cannot search it. Debian's /etc/kea is
// mode 0750 and owned by _kea. kea-dhcp4's AppArmor profile denies
// dac_override, so root cannot open files there.
func keaSyntaxCheckCredential(dir string) (*syscall.Credential, error) {
	fi, err := os.Stat(dir)
	if err != nil {
		return nil, err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return nil, nil
	}
	groups, err := os.Getgroups()
	if err != nil {
		return nil, err
	}
	gids := make([]uint32, len(groups))
	for i, g := range groups {
		gids[i] = uint32(g)
	}
	cred, err := keaSyntaxCredential(st.Uid, st.Gid, fi.Mode().Perm(), uint32(os.Geteuid()), uint32(os.Getegid()), gids)
	if err != nil {
		return nil, fmt.Errorf("DHCP configdir %s: %w", dir, err)
	}
	return cred, nil
}

func keaSyntaxCredential(uid, gid uint32, perm os.FileMode, euid, egid uint32, groups []uint32) (*syscall.Credential, error) {
	if perm&0o001 != 0 {
		return nil, nil
	}
	if uid == euid && perm&0o100 != 0 {
		return nil, nil
	}
	if perm&0o010 != 0 && (gid == egid || containsUint32(groups, gid)) {
		return nil, nil
	}
	if perm&0o100 == 0 {
		return nil, errors.New("config directory is not searchable by its owner")
	}
	return &syscall.Credential{Uid: uid, Gid: gid, Groups: []uint32{}}, nil
}

func containsUint32(xs []uint32, v uint32) bool {
	for _, x := range xs {
		if x == v {
			return true
		}
	}
	return false
}
