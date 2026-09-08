package internal

import (
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"path/filepath"
)

// ---------------------------------------------------------------------------
//   Zones
// ---------------------------------------------------------------------------

// Add a forward zone, such as example.com
func (dm *DnsManager) AddForwardZone(hostDnsTemplate *ConfigDNS_HostTemplate, configZone *ConfigZone) error {
	slog.Debug("Add forward", "zone", configZone)
	if err := VerifyDnsname(configZone.Name); err != nil {
		return fmt.Errorf("forward zone %s: %w", configZone.Name, err)
	}
	for _, zone := range *dm.ZonesForward {
		if zone.Name == configZone.Name {
			return errors.New("zonename already exist: " + configZone.Name)
		}
	}
	zone := new(Zone)
	zone.ConfigZone = configZone
	zone.Name = configZone.Name
	zone.Host = hostDnsTemplate
	*dm.ZonesForward = append(*dm.ZonesForward, zone)
	*dm.Zones = append(*dm.Zones, zone)
	return nil
}

// Add a reverse zone, such as
//
//	192.168.1.0/24
//	2a00:ff40:1000::/48
func (dm *DnsManager) AddReverseZone(hostDnsTemplate *ConfigDNS_HostTemplate, configZone *ConfigZone) error {
	slog.Debug("Add reverse", "zone", configZone)
	prefix1, err := netip.ParsePrefix(configZone.Name)
	if err != nil {
		return err
	}
	if prefix1 != prefix1.Masked() {
		return errors.New("reverse prefix has host bits set")
	}
	prefix1 = prefix1.Masked()
	addr1 := prefix1.Addr()
	plen := byte(prefix1.Bits())

	if configZone.Type == "reverse4" && !addr1.Is4() {
		return fmt.Errorf("reverse4 zone %s is not IPv4", configZone.Name)
	}
	if configZone.Type == "reverse6" && !addr1.Is6() {
		return fmt.Errorf("reverse6 zone %s is not IPv6", configZone.Name)
	}

	if addr1.Is4() {
		ip := addr1.As4()
		switch {
		case plen > 24:
			return errors.New("reverse ipv4 DNS with prefix length longer than 24 not implemented")

		case plen > 16:
			var iter byte = 1 << (24 - plen)
			for i := byte(0); i < iter; i++ {
				zone := new(Zone)
				zone.ConfigZone = configZone
				zone.Host = hostDnsTemplate
				zone.Name = fmt.Sprintf("%d.%d.%d.in-addr.arpa", ip[2]+i, ip[1], ip[0])
				*dm.Zones = append(*dm.Zones, zone)

				prefix2_str := fmt.Sprintf("%d.%d.%d.0/24", ip[0], ip[1], ip[2]+i)
				prefix2, err := netip.ParsePrefix(prefix2_str)
				if err != nil {
					return err
				}
				dm.ZoneReverse4.Insert(prefix2, zone)
			}

		case plen > 8:
			var iter byte = 1 << (16 - plen)
			for i := byte(0); i < iter; i++ {
				zone := new(Zone)
				zone.ConfigZone = configZone
				zone.Host = hostDnsTemplate
				zone.Name = fmt.Sprintf("%d.%d.in-addr.arpa", ip[1]+i, ip[0])
				*dm.Zones = append(*dm.Zones, zone)

				prefix2_str := fmt.Sprintf("%d.%d.0.0/16", ip[0], ip[1]+i)
				prefix2, err := netip.ParsePrefix(prefix2_str)
				if err != nil {
					return err
				}
				dm.ZoneReverse4.Insert(prefix2, zone)
			}

		case plen == 8:
			zone := new(Zone)
			zone.ConfigZone = configZone
			zone.Host = hostDnsTemplate
			zone.Name = fmt.Sprintf("%d.in-addr.arpa", ip[0])
			*dm.Zones = append(*dm.Zones, zone)

			prefix2_str := fmt.Sprintf("%d.0.0.0/8", ip[0])
			prefix2, err := netip.ParsePrefix(prefix2_str)
			if err != nil {
				return err
			}
			dm.ZoneReverse4.Insert(prefix2, zone)

		default:
			return errors.New("reverse ipv4 DNS with prefix length less than 8 not implemented")
		}
	} else if addr1.Is6() {
		if plen < 4 {
			return errors.New("reverse DNS IPv6 prefix length must be at least 4")
		}
		if plen&3 != 0 {
			return errors.New("reverse DNS IPv6 prefix length must be on a 4 bit/nibble boundary")
		}
		tmp1 := ReverseIpv6Addr(addr1)
		cut := int(128-plen) / 2
		if cut < 0 || cut >= len(tmp1) {
			return fmt.Errorf("internal error: IPv6 reverse cut %d for prefix length %d", cut, plen)
		}
		zone := new(Zone)
		zone.ConfigZone = configZone
		zone.Host = hostDnsTemplate
		zone.Name = tmp1[cut:] + ".ip6.arpa"
		*dm.Zones = append(*dm.Zones, zone)
		dm.ZoneReverse6.Insert(prefix1, zone)
	} else {
		return errors.New("reverse DNS, unknown address type: " + configZone.Name)
	}
	return nil
}

// Go through configuration of zones, and create internal data structures
func (dm *DnsManager) LoadZones() error {
	for _, host := range dm.C.Dnsmgr2 {
		if host.HostDnsTemplate == "" {
			if len(host.Zones) > 0 {
				return errors.New("zones require host_dns_template")
			}
		} else {
			hostDnsTemplate, ok := dm.C.DNS.HostTemplates[host.HostDnsTemplate]
			if !ok {
				return errors.New("unknown Host DNS template: " + host.HostDnsTemplate)
			}
			for i := range host.Zones {
				confZone := &host.Zones[i]
				switch confZone.Type {
				case "forward":
					if err := dm.AddForwardZone(&hostDnsTemplate, confZone); err != nil {
						return err
					}
				case "reverse4", "reverse6":
					if err := dm.AddReverseZone(&hostDnsTemplate, confZone); err != nil {
						return err
					}
				default:
					return errors.New("unknown zone type: " + confZone.Type)
				}
			}
			for _, zone := range *dm.Zones {
				slog.Info("Manage", "dns-zone", zone.Name)
			}
		}
		if host.HostDhcpTemplate != "" {
			if _, ok := dm.C.DHCP.HostTemplates[host.HostDhcpTemplate]; !ok {
				return errors.New("unknown Host DHCP template: " + host.HostDhcpTemplate)
			}
		} else if len(host.Prefixes) > 0 {
			return errors.New("prefixes require host_dhcp_template")
		}
		for _, p := range host.Prefixes {
			if _, err := resolvePrefix(p); err != nil {
				return err
			}
			slog.Info("Manage", "dhcp-prefix", p.Name)
		}
	}
	return nil
}

func (dm *DnsManager) Restart() error {
	slog.Debug("DnsMgr2.Restart()")
	for _, dest := range dm.C.Dnsmgr2 {
		if dest.HostDnsTemplate != "" {
			hostDnsTemplate, ok := dm.C.DNS.HostTemplates[dest.HostDnsTemplate]
			if !ok {
				return errors.New("unknown Host DNS template: " + dest.HostDnsTemplate)
			}
			switch hostDnsTemplate.Type {
			case "isc_bind":
				d := NewISCBINDManager(DNSManagerOpt{
					ConfigDNS:  &dm.C.DNS,
					ConfigData: dm.C.Dnsmgr2,
					Zones:      *dm.Zones,
				})
				if err := d.Restart(&hostDnsTemplate); err != nil {
					return err
				}
			default:
				return errors.New("unknown DnsTemplate type:" + hostDnsTemplate.Type)
			}
		}
		if err := dm.restartDHCP(dest); err != nil {
			return err
		}
	}
	return nil
}

func (dm *DnsManager) Status() error {
	slog.Debug("DnsMgr2.Status()")
	if err := dm.LoadZones(); err != nil {
		return err
	}
	for _, dest := range dm.C.Dnsmgr2 {
		if dest.HostDnsTemplate != "" {
			hostDnsTemplate, ok := dm.C.DNS.HostTemplates[dest.HostDnsTemplate]
			if !ok {
				return errors.New("unknown Host DNS template: " + dest.HostDnsTemplate)
			}
			switch hostDnsTemplate.Type {
			case "isc_bind":
				d := NewISCBINDManager(DNSManagerOpt{
					ConfigDNS:  &dm.C.DNS,
					ConfigData: dm.C.Dnsmgr2,
					Zones:      *dm.Zones,
				})
				if err := d.Status(&hostDnsTemplate); err != nil {
					return err
				}
			default:
				return errors.New("unknown DnsTemplate type:" + hostDnsTemplate.Type)
			}
		}
		if dest.HostDhcpTemplate != "" {
			host, ok := dm.C.DHCP.HostTemplates[dest.HostDhcpTemplate]
			if !ok {
				return errors.New("unknown Host DHCP template: " + dest.HostDhcpTemplate)
			}
			k := NewKeaDHCPManager(KeaDHCPManagerOpt{Host: &host})
			if host.IPv4.Enable {
				if err := k.Status(&host.IPv4, "DHCPv4"); err != nil {
					return err
				}
			}
			if host.IPv6.Enable {
				if err := k.Status(&host.IPv6, "DHCPv6"); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// Sync all destinations
func (dm *DnsManager) Sync() error {
	lockPath := dm.lockPath()
	if lockPath != "" {
		lock, err := AcquireLock(lockPath)
		if err != nil {
			return err
		}
		defer lock.Close()
	}

	needsDNS := false
	for _, dest := range dm.C.Dnsmgr2 {
		if dest.HostDnsTemplate != "" {
			needsDNS = true
			break
		}
	}
	if needsDNS {
		db, err := ConnectMigrate(dm.C.Dbfile)
		if err != nil {
			return err
		}
		dm.DB = db
		defer CloseDB(db)
	}

	for _, dest := range dm.C.Dnsmgr2 {
		if dest.HostDnsTemplate == "" && dest.HostDhcpTemplate == "" {
			return errors.New("dnsmgr2 entry needs host_dns_template or host_dhcp_template")
		}
		if dest.HostDnsTemplate != "" {
			hostDnsTemplate, ok := dm.C.DNS.HostTemplates[dest.HostDnsTemplate]
			if !ok {
				return errors.New("unknown Host DNS template: " + dest.HostDnsTemplate)
			}
			switch hostDnsTemplate.Type {
			case "isc_bind":
				d := NewISCBINDManager(DNSManagerOpt{
					Dbfile:     dm.C.Dbfile,
					DB:         dm.DB,
					ConfigDNS:  &dm.C.DNS,
					ConfigData: dm.C.Dnsmgr2,
					Zones:      *dm.Zones,
				})
				err := d.PreUpdate()
				if err != nil {
					return err
				}
				err = d.Update(&hostDnsTemplate, false)
				if err != nil {
					return err
				}
				err = d.UpdateCommit(&hostDnsTemplate)
				if err != nil {
					return err
				}
			default:
				return errors.New("unknown DnsTemplate type:" + hostDnsTemplate.Type)
			}
		}
		if err := dm.syncDHCP(dest); err != nil {
			return err
		}
	}
	return nil
}

func (dm *DnsManager) lockPath() string {
	if dm.C.Dbfile != "" {
		return dm.C.Dbfile + ".lock"
	}
	for _, dest := range dm.C.Dnsmgr2 {
		if dest.HostDnsTemplate != "" {
			if h, ok := dm.C.DNS.HostTemplates[dest.HostDnsTemplate]; ok && h.Tmpdir != "" {
				return filepath.Join(h.Tmpdir, "dnsmgr2.lock")
			}
		}
		if dest.HostDhcpTemplate != "" {
			if h, ok := dm.C.DHCP.HostTemplates[dest.HostDhcpTemplate]; ok {
				if h.IPv4.Tmpdir != "" {
					return filepath.Join(h.IPv4.Tmpdir, "dnsmgr2.lock")
				}
				if h.IPv6.Tmpdir != "" {
					return filepath.Join(h.IPv6.Tmpdir, "dnsmgr2.lock")
				}
			}
		}
	}
	return ""
}

func (dm *DnsManager) syncDHCP(dest ConfigDataType) error {
	if dest.HostDhcpTemplate == "" {
		return nil
	}
	host, ok := dm.C.DHCP.HostTemplates[dest.HostDhcpTemplate]
	if !ok {
		return errors.New("unknown Host DHCP template: " + dest.HostDhcpTemplate)
	}
	typ := host.Type
	if typ == "" {
		typ = "isc_kea"
	}
	switch typ {
	case "isc_kea":
		k := NewKeaDHCPManager(KeaDHCPManagerOpt{
			ConfigDHCP: &dm.C.DHCP,
			Host:       &host,
			Prefixes:   dest.Prefixes,
			Zones:      *dm.Zones,
		})
		if err := k.Update(); err != nil {
			return err
		}
		return k.UpdateCommit()
	default:
		return errors.New("unknown DHCP template type: " + typ)
	}
}

func (dm *DnsManager) restartDHCP(dest ConfigDataType) error {
	if dest.HostDhcpTemplate == "" {
		return nil
	}
	host, ok := dm.C.DHCP.HostTemplates[dest.HostDhcpTemplate]
	if !ok {
		return errors.New("unknown Host DHCP template: " + dest.HostDhcpTemplate)
	}
	typ := host.Type
	if typ == "" {
		typ = "isc_kea"
	}
	switch typ {
	case "isc_kea":
		k := NewKeaDHCPManager(KeaDHCPManagerOpt{Host: &host})
		if host.IPv4.Enable {
			if err := k.Restart(&host.IPv4); err != nil {
				return err
			}
		}
		if host.IPv6.Enable {
			if err := k.Restart(&host.IPv6); err != nil {
				return err
			}
		}
		return nil
	default:
		return errors.New("unknown DHCP template type: " + typ)
	}
}
