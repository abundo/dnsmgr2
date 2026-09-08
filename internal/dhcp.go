package internal

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
)

// resolvedPrefix is a ConfigPrefix after defaults and validation.
type resolvedPrefix struct {
	Prefix     netip.Prefix
	HasRange   bool
	RangeStart netip.Addr
	RangeEnd   netip.Addr
	Gateway    netip.Addr
	SubnetMask string // IPv4 dotted-quad; empty for IPv6
	DNSServers []string
}

func resolvePrefix(cfg ConfigPrefix) (*resolvedPrefix, error) {
	if strings.TrimSpace(cfg.Name) == "" {
		return nil, errors.New("DHCP prefix name is empty")
	}
	prefix, err := netip.ParsePrefix(cfg.Name)
	if err != nil {
		return nil, fmt.Errorf("DHCP prefix %s: %w", cfg.Name, err)
	}
	if prefix != prefix.Masked() {
		return nil, fmt.Errorf("DHCP prefix %s has host bits set", cfg.Name)
	}
	prefix = prefix.Masked()

	rp := &resolvedPrefix{Prefix: prefix}

	if strings.TrimSpace(cfg.Range) != "" {
		start, end, err := parseDHCPRange(cfg.Range)
		if err != nil {
			return nil, fmt.Errorf("DHCP prefix %s range: %w", cfg.Name, err)
		}
		if start.BitLen() != prefix.Addr().BitLen() {
			return nil, fmt.Errorf("DHCP prefix %s range address family does not match prefix", cfg.Name)
		}
		if !prefix.Contains(start) || !prefix.Contains(end) {
			return nil, fmt.Errorf("DHCP prefix %s range %s is outside the prefix", cfg.Name, cfg.Range)
		}
		if start.Compare(end) > 0 {
			return nil, fmt.Errorf("DHCP prefix %s range start is after end", cfg.Name)
		}
		rp.HasRange = true
		rp.RangeStart = start
		rp.RangeEnd = end
	}

	if strings.TrimSpace(cfg.Gateway) != "" {
		gw, err := netip.ParseAddr(strings.TrimSpace(cfg.Gateway))
		if err != nil {
			return nil, fmt.Errorf("DHCP prefix %s gateway: %w", cfg.Name, err)
		}
		if gw.BitLen() != prefix.Addr().BitLen() {
			return nil, fmt.Errorf("DHCP prefix %s gateway address family does not match prefix", cfg.Name)
		}
		rp.Gateway = gw
	} else if prefix.Addr().Is4() {
		rp.Gateway = defaultGateway(prefix)
	}

	if prefix.Addr().Is4() {
		if strings.TrimSpace(cfg.SubnetMask) != "" {
			mask := strings.TrimSpace(cfg.SubnetMask)
			ip := net.ParseIP(mask)
			if ip == nil || ip.To4() == nil {
				return nil, fmt.Errorf("DHCP prefix %s subnet_mask is not an IPv4 mask: %s", cfg.Name, cfg.SubnetMask)
			}
			rp.SubnetMask = ip.To4().String()
		} else {
			rp.SubnetMask = ipv4SubnetMask(prefix.Bits())
		}
	} else if strings.TrimSpace(cfg.SubnetMask) != "" {
		return nil, fmt.Errorf("DHCP prefix %s subnet_mask is only valid for IPv4", cfg.Name)
	}

	for i, s := range cfg.DNSServers {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if _, err := netip.ParseAddr(s); err != nil {
			return nil, fmt.Errorf("DHCP prefix %s dns_servers[%d] is not an IP address: %s", cfg.Name, i, s)
		}
		rp.DNSServers = append(rp.DNSServers, s)
	}

	return rp, nil
}

func parseDHCPRange(s string) (start, end netip.Addr, err error) {
	s = strings.TrimSpace(s)
	var left, right string
	if i := strings.Index(s, " - "); i >= 0 {
		left, right = s[:i], s[i+3:]
	} else if i := strings.LastIndex(s, "-"); i >= 0 {
		left, right = s[:i], s[i+1:]
	} else {
		return netip.Addr{}, netip.Addr{}, errors.New("must be start-end")
	}
	start, err = netip.ParseAddr(strings.TrimSpace(left))
	if err != nil {
		return netip.Addr{}, netip.Addr{}, fmt.Errorf("start address: %w", err)
	}
	end, err = netip.ParseAddr(strings.TrimSpace(right))
	if err != nil {
		return netip.Addr{}, netip.Addr{}, fmt.Errorf("end address: %w", err)
	}
	if start.BitLen() != end.BitLen() {
		return netip.Addr{}, netip.Addr{}, errors.New("start and end address family mismatch")
	}
	return start, end, nil
}

// defaultGateway is the first usable address: network + 1 for prefixes with
// a network/broadcast pair, otherwise the prefix address itself.
func defaultGateway(prefix netip.Prefix) netip.Addr {
	addr := prefix.Addr()
	if addr.Is4() && prefix.Bits() <= 30 {
		return addr.Next()
	}
	if addr.Is6() && prefix.Bits() <= 126 {
		return addr.Next()
	}
	return addr
}

func ipv4SubnetMask(bits int) string {
	m := net.CIDRMask(bits, 32)
	return net.IP(m).String()
}

func findPrefix(prefixes []*resolvedPrefix, ip netip.Addr) *resolvedPrefix {
	var best *resolvedPrefix
	bestBits := -1
	for _, p := range prefixes {
		if p.Prefix.Contains(ip) && p.Prefix.Bits() > bestBits {
			best = p
			bestBits = p.Prefix.Bits()
		}
	}
	return best
}

func recordHostname(zone *Zone, record *Record) string {
	zoneName := strings.TrimSuffix(zone.Name, ".")
	name := strings.TrimSuffix(record.Name, ".")
	if name == "" || name == "@" {
		return zoneName
	}
	if strings.HasSuffix(strings.ToLower(name), "."+strings.ToLower(zoneName)) ||
		strings.EqualFold(name, zoneName) {
		return name
	}
	return name + "." + zoneName
}
