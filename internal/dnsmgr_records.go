package internal

import (
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"sort"
	"strconv"
	"strings"

	"github.com/seancfoley/ipaddress-go/ipaddr"
)

type ZonesType []*Zone
type RecordsType []*Record

type Zone struct {
	Name       string
	ConfigZone *ConfigZone

	DNS     *ConfigDNS_ZoneTemplate
	SOA     *ConfigDNS_SOA_template
	Host    *ConfigDNS_HostTemplate
	Zone    *Zone
	DstFile string
	TmpFile string
	Records RecordsType
}

type Record struct {
	Name    string
	TTL     int64
	Type    string
	Value   string
	MAC     string
	Forward bool // generate forwarding records?
	Reverse bool // generate PTR record?
}

// ---------------------------------------------------------------------------
//   Records
// ---------------------------------------------------------------------------

func (dm *DnsManager) PrintRecords() {
	fmt.Printf("Name                                      TTL    Type      Value\n")
	fmt.Printf("----------------------------------------  -----  --------  ------------------\n")
	for _, zone := range *dm.Zones {
		for _, record := range zone.Records {
			fmt.Printf("%-40s  ", record.Name)
			if record.TTL > 0 {
				fmt.Printf("%5d  ", record.TTL)

			} else {
				fmt.Printf("       ")
			}
			fmt.Printf("%-8s  %s\n", record.Type, record.Value)
		}
	}
}

// Add a record to a zone
// Handle generation of reverse DNS records
func (dm *DnsManager) AddForwardRecord(domain string, record *Record) error {
	slog.Debug("AddForward", "record", record)
	if strings.TrimSpace(domain) == "" {
		return errors.New("record before $DOMAIN")
	}
	if record.Forward {
		var zone *Zone
		for _, zoneLoop := range *dm.ZonesForward {
			if zoneLoop.Name == domain {
				zone = zoneLoop
				zone.Records = append(zone.Records, record)
				break
			}
		}
		if zone == nil {
			return fmt.Errorf("unknown domain %q (missing zone or $DOMAIN)", domain)
		}
	}
	if (record.Type == "A" || record.Type == "AAAA") && record.Reverse {
		r := new(Record)
		r.Name = record.Value
		r.Type = "PTR"
		if record.Name == "@" {
			r.Value = domain + "."
		} else if strings.HasSuffix(record.Name, ".") {
			r.Value = record.Name
		} else {
			r.Value = fmt.Sprintf("%s.%s.", record.Name, domain)
		}
		if err := dm.AddReverseRecord(domain, r); err != nil {
			return err
		}
	}

	return nil
}

func (dm *DnsManager) AddReverseRecord(domain string, record *Record) error {
	slog.Debug("AddReverse", "record", record)
	addr, err := netip.ParseAddr(record.Name)
	if err != nil {
		return err
	}

	switch addr.BitLen() {
	case 32: // IPv4
		zone, ok := dm.ZoneReverse4.Lookup(addr)
		if !ok {
			slog.Warn("no reverse zone for address, skipping PTR", "address", record.Name)
			return nil
		}
		name := ReverseIpv4Addr(addr) + ".in-addr.arpa"
		rel, err := reverseOwnerRelative(name, zone.Name)
		if err != nil {
			return err
		}
		record.Name = rel
		zone.Records = append(zone.Records, record)

	case 128: // IPv6
		zone, ok := dm.ZoneReverse6.Lookup(addr)
		if !ok {
			slog.Warn("no reverse zone for address, skipping PTR", "address", record.Name)
			return nil
		}
		name := ReverseIpv6Addr(addr) + ".ip6.arpa"
		rel, err := reverseOwnerRelative(name, zone.Name)
		if err != nil {
			return err
		}
		record.Name = rel
		zone.Records = append(zone.Records, record)

	default:
		return errors.New("Internal error, incorrect BitLen()")
	}
	return nil
}

func reverseOwnerRelative(fqdn, zoneName string) (string, error) {
	fqdn = strings.TrimSuffix(fqdn, ".")
	zoneName = strings.TrimSuffix(zoneName, ".")
	if !strings.HasSuffix(fqdn, zoneName) {
		return "", fmt.Errorf("reverse name %s is not in zone %s", fqdn, zoneName)
	}
	rel := strings.TrimSuffix(fqdn, zoneName)
	rel = strings.TrimSuffix(rel, ".")
	if rel == "" {
		return "@", nil
	}
	return rel, nil
}

func (dm *DnsManager) VerifyRecords() error {
	// Verify correctness of records
	var err error
	for _, zone := range *dm.Zones {
		for _, record := range zone.Records {
			if record.Name != "@" {
				if err := VerifyDnsname(record.Name); err != nil {
					return err
				}
			}
			if record.TTL < 0 || record.TTL > maxTTL {
				return errors.New("record TTL outside allowed values")
			}
			switch record.Type {
			case "A":
				ipStr := ipaddr.NewIPAddressString(record.Value)
				ip, err := ipStr.ToAddress()
				if err != nil {
					return err
				}
				if !ip.IsIPv4() {
					return errors.New("value of A record is not an IPv4 address")
				}
				if ip == nil {
					return errors.New("incorrect A record")
				}
			case "AAAA":
				ipStr := ipaddr.NewIPAddressString(record.Value)
				ip, err := ipStr.ToAddress()
				if err != nil {
					return err
				}
				if !ip.IsIPv6() {
					return errors.New("value of AAAA record is not an IPv6 address")
				}
				if ip == nil {
					return errors.New("incorrect value of AAAA record")
				}
			case "CNAME":
				err = VerifyDnsname(record.Value)
				if err != nil {
					return err
				}
			case "MX":
				// priority (uint16), destination
				// destination must point to one or more A/AAAA, and must not point to CNAME
				if err = verifyMX(record.Value); err != nil {
					return err
				}
				dest := strings.Fields(record.Value)[1]
				if err = dm.verifyMXDestination(zone, dest); err != nil {
					return err
				}
			case "NS":
				err = VerifyDnsname(record.Value)
				if err != nil {
					return err
				}
			case "PTR":
				err = VerifyDnsname(record.Value)
				if err != nil {
					return err
				}
			case "SRV":
				if err = verifySRV(record.Value); err != nil {
					return err
				}
			case "SSHFP":
				if err = verifySSHFP(record.Value); err != nil {
					return err
				}
			case "TLSA":
				if err = verifyTLSA(record.Value); err != nil {
					return err
				}
			case "TSIG":
				return errors.New("TSIG is not a supported zone record type")
			case "TXT":
				// start and end with double quote
				if err = verifyTXT(record.Value); err != nil {
					return err
				}
			default:
				// accept all unknown type/values
			}
		}
	}
	return nil
}

func verifySRV(value string) error {
	tmp := strings.Fields(value)
	if len(tmp) != 4 {
		return errors.New("SRV record must have priority, weight, port and target")
	}
	if _, err := strconv.ParseUint(tmp[0], 10, 16); err != nil {
		return errors.New("SRV priority must be an integer 0-65535")
	}
	if _, err := strconv.ParseUint(tmp[1], 10, 16); err != nil {
		return errors.New("SRV weight must be an integer 0-65535")
	}
	if _, err := strconv.ParseUint(tmp[2], 10, 16); err != nil {
		return errors.New("SRV port must be an integer 0-65535")
	}
	if tmp[3] == "." {
		return nil
	}
	return VerifyDnsname(tmp[3])
}

func verifySSHFP(value string) error {
	tmp := strings.Fields(value)
	if len(tmp) != 3 {
		return errors.New("SSHFP record must have algorithm, fingerprint type and fingerprint")
	}
	if _, err := strconv.ParseUint(tmp[0], 10, 8); err != nil {
		return errors.New("SSHFP algorithm must be an integer 0-255")
	}
	fptype, err := strconv.ParseUint(tmp[1], 10, 8)
	if err != nil {
		return errors.New("SSHFP fingerprint type must be an integer 0-255")
	}
	fp := strings.NewReplacer(":", "", ".", "").Replace(tmp[2])
	cert, err := hex.DecodeString(fp)
	if err != nil {
		return errors.New("SSHFP fingerprint must be hexadecimal")
	}
	switch fptype {
	case 1:
		if len(cert) != 20 {
			return errors.New("SSHFP SHA-1 fingerprint must be 20 bytes (40 hex characters)")
		}
	case 2:
		if len(cert) != 32 {
			return errors.New("SSHFP SHA-256 fingerprint must be 32 bytes (64 hex characters)")
		}
	}
	return nil
}

func verifyMX(value string) error {
	tmp := strings.Fields(value)
	if len(tmp) != 2 {
		return errors.New("MX record must have priority and destination")
	}
	if _, err := strconv.ParseUint(tmp[0], 10, 16); err != nil {
		return errors.New("MX priority must be an integer 0-65535")
	}
	dest := tmp[1]
	if dest == "" || dest == "." {
		return errors.New("MX destination is empty")
	}
	if _, err := netip.ParseAddr(strings.TrimSuffix(dest, ".")); err == nil {
		return errors.New("MX destination must be a domain name, not an IP address")
	}
	if err := VerifyDnsname(dest); err != nil {
		return err
	}
	return nil
}

// verifyMXDestination checks that dest is not a CNAME and, when the name
// is inside a managed zone, that it has at least one A or AAAA record.
func (dm *DnsManager) verifyMXDestination(zone *Zone, dest string) error {
	if owner, inZone := resolveOwnerInZone(zone.Name, dest); inZone {
		return checkMXTargetRecords(zone, owner, dest)
	}
	if dm.ZonesForward != nil {
		for _, z := range *dm.ZonesForward {
			if owner, inZone := resolveOwnerInZone(z.Name, dest); inZone {
				return checkMXTargetRecords(z, owner, dest)
			}
		}
	}
	return nil
}

func resolveOwnerInZone(zoneName, dest string) (owner string, inZone bool) {
	absolute := strings.HasSuffix(dest, ".")
	dest = strings.TrimSuffix(dest, ".")
	zoneName = strings.TrimSuffix(zoneName, ".")
	if dest == "@" {
		return "@", true
	}
	if strings.EqualFold(dest, zoneName) {
		return "@", true
	}
	suffix := "." + zoneName
	if len(dest) > len(suffix) && strings.EqualFold(dest[len(dest)-len(suffix):], suffix) {
		return dest[:len(dest)-len(suffix)], true
	}
	if !absolute {
		return dest, true
	}
	return dest, false
}

func checkMXTargetRecords(zone *Zone, owner, dest string) error {
	var found, hasAddr, hasCNAME bool
	for _, r := range zone.Records {
		if !ownerNamesEqual(r.Name, owner) {
			continue
		}
		found = true
		switch r.Type {
		case "CNAME":
			hasCNAME = true
		case "A", "AAAA":
			hasAddr = true
		}
	}
	if hasCNAME {
		return fmt.Errorf("MX destination %s must not point to a CNAME", dest)
	}
	if !found || !hasAddr {
		return fmt.Errorf("MX destination %s must point to one or more A/AAAA records", dest)
	}
	return nil
}

func ownerNamesEqual(a, b string) bool {
	a = strings.TrimSuffix(a, ".")
	b = strings.TrimSuffix(b, ".")
	if a == "@" || b == "@" {
		return a == b
	}
	return strings.EqualFold(a, b)
}

func verifyTLSA(value string) error {
	tmp := strings.Fields(value)
	if len(tmp) < 4 {
		return errors.New("TLSA record must have usage, selector, matching-type and certificate data")
	}
	if _, err := strconv.ParseUint(tmp[0], 10, 8); err != nil {
		return errors.New("TLSA usage must be an integer 0-255")
	}
	if _, err := strconv.ParseUint(tmp[1], 10, 8); err != nil {
		return errors.New("TLSA selector must be an integer 0-255")
	}
	matching, err := strconv.ParseUint(tmp[2], 10, 8)
	if err != nil {
		return errors.New("TLSA matching-type must be an integer 0-255")
	}

	certHex := strings.NewReplacer(":", "", ".", "").Replace(strings.Join(tmp[3:], ""))
	if certHex == "" {
		return errors.New("TLSA certificate association data must not be empty")
	}
	cert, err := hex.DecodeString(certHex)
	if err != nil {
		return errors.New("TLSA certificate association data must be hexadecimal")
	}
	switch matching {
	case 1:
		if len(cert) != 32 {
			return errors.New("TLSA SHA-256 certificate data must be 32 bytes (64 hex characters)")
		}
	case 2:
		if len(cert) != 64 {
			return errors.New("TLSA SHA-512 certificate data must be 64 bytes (128 hex characters)")
		}
	}
	return nil
}

func verifyTXT(value string) error {
	value = strings.TrimSpace(value)
	if value == "" {
		return errors.New("TXT record value is empty")
	}

	i := 0
	n := 0
	for i < len(value) {
		for i < len(value) && (value[i] == ' ' || value[i] == '\t') {
			i++
		}
		if i >= len(value) {
			break
		}
		if value[i] != '"' {
			return errors.New("TXT record must start and end with double quote")
		}
		i++
		start := i
		escaped := false
		closed := false
		for i < len(value) {
			c := value[i]
			if escaped {
				escaped = false
				i++
				continue
			}
			if c == '\\' {
				escaped = true
				i++
				continue
			}
			if c == '"' {
				if i-start > 255 {
					return errors.New("TXT record string exceeds 255 characters")
				}
				closed = true
				i++
				n++
				break
			}
			i++
		}
		if !closed {
			return errors.New("TXT record has unclosed quote")
		}
	}
	if n == 0 {
		return errors.New("TXT record must start and end with double quote")
	}
	return nil
}

// ---------------------------------------------------------------------------
//   Other
// ---------------------------------------------------------------------------

// Load all sources
func (dm *DnsManager) Load() error {
	if err := dm.LoadZones(); err != nil {
		return err
	}
	for _, source := range dm.C.Sources {
		switch source.Type {
		case "file":
			slog.Info("Load records", "source-file", source.Name)
			err := SrcfileLoad(dm, source.Name)
			if err != nil {
				return err
			}
		case "json":
			slog.Info("Load records", "source-json", source.Name)
			err := SrcJSONLoad(dm, source.Name)
			if err != nil {
				return err
			}
		default:
			return errors.New("unknown source type: " + source.Type)
		}

		// Sort all Records by Name
		// Makes comparision of files predictable
		for _, zone := range *dm.Zones {
			sort.Slice(zone.Records, func(i, j int) bool {
				return zone.Records[i].Name < zone.Records[j].Name
			})
		}

		slog.Debug("Verify loaded records")
		err := dm.VerifyRecords()
		if err != nil {
			return err
		}
	}
	return nil
}
