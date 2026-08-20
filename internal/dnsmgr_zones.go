package internal

import (
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
)

// ---------------------------------------------------------------------------
//   Zones
// ---------------------------------------------------------------------------

// Add a forward zone, such as example.com
func (dm *DnsManager) AddForwardZone(hostDnsTemplate *ConfigDNS_HostTemplate, configZone *ConfigZone) error {
	slog.Debug("Add forward", "zone", configZone)
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
//	2a00:ff40:1000:://48
func (dm *DnsManager) AddReverseZone(hostDnsTemplate *ConfigDNS_HostTemplate, configZone *ConfigZone) error {
	var err error
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

	if addr1.Is4() {
		ip := addr1.As4()
		switch {
		case plen > 24:
			switch plen {
			case 32:
				// 10.1.2.0/32
				// 0.1.2.10.in-addr.arpa
			case 31:
				// 10.1.2.0/31
				// 0-1.2.1.10.in-addr.arpa
			case 30:
				// 10.1.2.0/30
				// 0-3.2.1.10.in-addr.arpa
			case 29:
				// 10.1.2.0/29
				// 0-7.2.1.10.in-addr.arpa
			case 28:
				// 10.1.2.0/28
				// 0-15.2.1.10.in-addr.arpa
			case 27:
				// 10.1.2.0/27
				// 0-31.2.1.10.in-addr.arpa
			case 26:
				// 10.1.2.0/26
				// 0-63.2.1.10.in-addr.arpa
			case 25:
				// 10.1.2.0/25
				// 0-127.2.1.10.in-addr.arpa
			}
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
				prefix2, _ := netip.ParsePrefix(prefix2_str)
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
				prefix2, _ := netip.ParsePrefix(prefix2_str)
				dm.ZoneReverse4.Insert(prefix2, zone)
			}

		case plen == 8:
			zone := new(Zone)
			zone.ConfigZone = configZone
			zone.Host = hostDnsTemplate
			zone.Name = fmt.Sprintf("%d.%d.in-addr.arpa", ip[1], ip[0])
			*dm.Zones = append(*dm.Zones, zone)

			prefix2_str := fmt.Sprintf("%d.0.0/8", ip[0])
			prefix2, _ := netip.ParsePrefix(prefix2_str)
			dm.ZoneReverse4.Insert(prefix2, zone)

		default:
			return errors.New("reverse ipv4 DNS with prefix length less than 8 not implemented")
		}
	} else if addr1.Is6() {
		if plen&3 != 0 {
			return errors.New("reverse DNS IPv6 prefix length must be on a 4 bit/nibble boundary")
		}
		tmp1 := ReverseIpv6Addr(addr1)
		cut := (128 - plen) / 2
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
		hostDnsTemplate, ok := dm.C.DNS.HostTemplates[host.HostDnsTemplate]
		if !ok {
			return errors.New("unknown Host DNS template: " + host.HostDnsTemplate)
		}
		for _, confZone := range host.Zones {
			switch confZone.Type {
			case "forward":
				dm.AddForwardZone(&hostDnsTemplate, &confZone)
			case "reverse4", "reverse6":
				dm.AddReverseZone(&hostDnsTemplate, &confZone)
			default:
				return errors.New("unknown zone type: " + confZone.Type)
			}
		}
		for _, zone := range *dm.Zones {
			slog.Info("Manage", "dns-zone", zone.Name)
		}
	}
	return nil
}

func (dm *DnsManager) Restart() error {
	slog.Debug("DnsMgr2.Restart()")
	for _, dest := range dm.C.Dnsmgr2 {
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
	return nil
}

func (dm *DnsManager) Status() error {
	slog.Debug("DnsMgr2.Status()")
	for _, dest := range dm.C.Dnsmgr2 {
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
	return nil
}

// Sync all destinations
func (dm *DnsManager) Sync() error {
	var err error
	for _, dest := range dm.C.Dnsmgr2 {
		hostDnsTemplate, ok := dm.C.DNS.HostTemplates[dest.HostDnsTemplate]
		if !ok {
			return errors.New("unknown Host DNS template: " + dest.HostDnsTemplate)
		}
		switch hostDnsTemplate.Type {
		case "isc_bind":
			d := NewISCBINDManager(DNSManagerOpt{
				Dbfile:     dm.C.Dbfile,
				ConfigDNS:  &dm.C.DNS,
				ConfigData: dm.C.Dnsmgr2,
				Zones:      *dm.Zones,
			})
			err = d.PreUpdate()
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
	return nil
}
