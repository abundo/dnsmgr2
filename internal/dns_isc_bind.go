package internal

//
// ISC BIND driver
//

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"gorm.io/gorm"
)

type DNSManagerOpt struct {
	Dbfile     string
	DB         *gorm.DB
	ConfigDNS  *ConfigDNS
	ConfigData ConfigDataGroups
	Zones      ZonesType
}

type DNSManager struct {
	P DNSManagerOpt
}

// Create a manager, which handles the DNS server
func NewISCBINDManager(p DNSManagerOpt) *DNSManager {
	manager := new(DNSManager)
	manager.P = p
	return manager
}

func zoneFileRel(host *ConfigDNS_HostTemplate, zoneName string) string {
	if host == nil || host.Zonesfile == "" || host.Zonesfile == "{zone}" {
		return zoneName
	}
	return strings.ReplaceAll(host.Zonesfile, "{zone}", zoneName)
}

func (dns *DNSManager) serialDB() (*gorm.DB, error) {
	if dns.P.DB != nil {
		return dns.P.DB, nil
	}
	if dns.P.Dbfile == "" {
		return nil, errors.New("dbfile is empty")
	}
	db, err := ConnectMigrate(dns.P.Dbfile)
	if err != nil {
		return nil, err
	}
	dns.P.DB = db
	return db, nil
}

func (dns *DNSManager) Reload(zonename string, hostDnsTemplate *ConfigDNS_HostTemplate) error {
	slog.Debug("----- DNSManager.Reload() -----", "zonename", zonename)
	cmd := strings.ReplaceAll(hostDnsTemplate.CmdReloadZone, "{zone}", zonename)
	return RunCommand(cmd)
}

func (dns *DNSManager) ReloadAll(hostDnsTemplate *ConfigDNS_HostTemplate) error {
	slog.Debug("----- DNSManager.ReloadAll() -----")
	return RunCommand(hostDnsTemplate.CmdReloadAll)
}

func (dns *DNSManager) Restart(hostDnsTemplate *ConfigDNS_HostTemplate) error {
	slog.Debug("----- DNSManager.Restart() -----")
	return RunCommand(hostDnsTemplate.CmdRestart)
}

func (dns *DNSManager) Status(hostDnsTemplate *ConfigDNS_HostTemplate) error {
	slog.Debug("----- DNSManager.Status() -----")
	if hostDnsTemplate.CmdStatus != "" {
		return RunCommand(hostDnsTemplate.CmdStatus)
	}
	include, err := SafeJoin(hostDnsTemplate.Configdir, hostDnsTemplate.IncludeFile)
	if err != nil {
		return err
	}
	if _, err := os.Stat(include); err != nil {
		fmt.Printf("ISC BIND include %s: missing\n", include)
	} else {
		fmt.Printf("ISC BIND include %s: present\n", include)
	}
	for _, zone := range dns.P.Zones {
		rel := zoneFileRel(hostDnsTemplate, zone.Name)
		dst, err := SafeJoin(hostDnsTemplate.ZonesDir, rel)
		if err != nil {
			return err
		}
		if _, err := os.Stat(dst); err != nil {
			fmt.Printf("ISC BIND zone %s (%s): missing\n", zone.Name, dst)
		} else {
			fmt.Printf("ISC BIND zone %s (%s): present\n", zone.Name, dst)
		}
	}
	return nil
}

// Resolve all referenses in Config
func (dns *DNSManager) PreUpdate() error {
	for _, zone := range dns.P.Zones {
		confZone := zone.ConfigZone
		dnsTemplate, ok := dns.P.ConfigDNS.ZoneTemplates[confZone.DnsTemplate]
		if !ok {
			return errors.New("unknown DNS template: " + confZone.DnsTemplate)
		}
		zone.DNS = &dnsTemplate

		SOA, ok := dns.P.ConfigDNS.SOATemplates[dnsTemplate.SOA]
		if !ok {
			return errors.New("unknown SOA template: " + dnsTemplate.SOA)
		}
		if SOA.SerialFormat != "" && SOA.SerialFormat != "date_serial" {
			return fmt.Errorf("unsupported serial_format %q (only date_serial)", SOA.SerialFormat)
		}
		zone.SOA = &SOA
	}
	return nil
}

// Write one zonefile, optionally update SOA serial
func (dns *DNSManager) UpdateZone(host *ConfigDNS_HostTemplate, zone *Zone, newSerial bool) error {
	if err := os.MkdirAll(filepath.Dir(zone.TmpFile), 0o755); err != nil {
		return err
	}
	file, err := os.Create(zone.TmpFile)
	if err != nil {
		return err
	}
	defer file.Close()
	fmt.Fprintf(file, ";------------------------------------------------------------\n")
	fmt.Fprintf(file, "; Zone file for %s\n", zone.Name)
	fmt.Fprintf(file, "; WARNING! do not edit, dnsmgr2 will overwrite your changes\n")
	fmt.Fprintf(file, ";------------------------------------------------------------\n\n")

	if zone.DNS.DefaultTTL != "" {
		fmt.Fprintf(file, "$TTL %s\n", zone.DNS.DefaultTTL)
	}
	format := "%-35s  %5s  %-8s  %s\n"

	db, err := dns.serialDB()
	if err != nil {
		return err
	}
	serial, err := GetSerial(db, zone.Name, newSerial)
	if err != nil {
		return err
	}

	fmt.Fprintf(file, format, "@", "", "SOA", zone.SOA.Mname+" "+zone.SOA.Rname+" (")
	fmt.Fprintf(file, format, "", "", fmt.Sprintf("%14s ; serial", serial), "")
	fmt.Fprintf(file, format, "", "", fmt.Sprintf("%14d ; refresh", zone.SOA.Refresh), "")
	fmt.Fprintf(file, format, "", "", fmt.Sprintf("%14d ; retry", zone.SOA.Retry), "")
	fmt.Fprintf(file, format, "", "", fmt.Sprintf("%14d ; expire", zone.SOA.Expire), "")
	fmt.Fprintf(file, format, "", "", fmt.Sprintf("%14d ; minimum", zone.SOA.Minimum), "")
	fmt.Fprintf(file, format, "", "", ")", "")

	// Write NS records
	fmt.Fprintln(file, "")
	fmt.Fprintln(file, ";")
	fmt.Fprintln(file, "; NS records")
	fmt.Fprintln(file, ";")
	for _, record := range zone.DNS.NS {
		fmt.Fprintf(file, format, record.Name, record.TTL, record.Type, record.Value)
	}

	// Write records
	fmt.Fprintln(file, "")
	fmt.Fprintln(file, ";")
	fmt.Fprintln(file, "; Records")
	fmt.Fprintln(file, ";")

	var TTL string
	for _, record := range zone.Records {
		if record.TTL > 0 {
			TTL = strconv.FormatInt(record.TTL, 10)
		} else {
			TTL = ""
		}
		slog.Debug("zone record", "name", record.Name, "ttl", TTL, "type", record.Type, "value", record.Value)
		fmt.Fprintf(file, format, record.Name, TTL, record.Type, record.Value)
	}

	if err := file.Close(); err != nil {
		return err
	}

	return namedCheckZone(zone.Name, zone.TmpFile)
}

func namedCheckZone(zonename, filename string) error {
	cmd := exec.Command("named-checkzone", zonename, filename)
	out, err := cmd.CombinedOutput()
	output := strings.TrimSpace(string(out))
	if err != nil {
		if output != "" {
			slog.Error("named-checkzone", "zone", zonename, "file", filename, "err", err, "output", output)
			return fmt.Errorf("named-checkzone %s %s: %w\n%s", zonename, filename, err, output)
		}
		slog.Error("named-checkzone", "zone", zonename, "file", filename, "err", err)
		return fmt.Errorf("named-checkzone %s %s: %w", zonename, filename, err)
	}
	slog.Debug("named-checkzone validation ok", "zone", zonename)
	return nil
}

// Write all zone files
func (dns *DNSManager) Update(host *ConfigDNS_HostTemplate, newSerial bool) error {
	slog.Debug("----- DNSManager.Update() -----")

	includeFileStr, err := SafeJoin(host.Tmpdir, host.IncludeFile)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(includeFileStr), 0o755); err != nil {
		return err
	}
	slog.Info("Creating", "include-file", includeFileStr)
	includeFile, err := os.Create(includeFileStr)
	if err != nil {
		return err
	}
	defer includeFile.Close()
	fmt.Fprintf(includeFile, "//------------------------------------------------------------\n")
	fmt.Fprintf(includeFile, "// Zone definitions\n")
	fmt.Fprintf(includeFile, "// WARNING! do not edit, dnsmgr2 will overwrite your changes\n")
	fmt.Fprintf(includeFile, "//------------------------------------------------------------\n")

	for _, zone := range dns.P.Zones {
		rel := zoneFileRel(host, zone.Name)
		zone.DstFile, err = SafeJoin(host.ZonesDir, rel)
		if err != nil {
			return fmt.Errorf("zone %s dest path: %w", zone.Name, err)
		}
		zone.TmpFile, err = SafeJoin(host.Tmpdir, rel)
		if err != nil {
			return fmt.Errorf("zone %s tmp path: %w", zone.Name, err)
		}

		slog.Info("Creating", "zone", zone.TmpFile)
		fmt.Fprintf(includeFile, "\nzone \"%s\" {\n", zone.Name)
		fmt.Fprintf(includeFile, "    type primary;\n")
		fmt.Fprintf(includeFile, "    file \"%s\";\n", zone.DstFile)
		if zone.DNS.DNSSECpolicy != "" {
			fmt.Fprintf(includeFile, "    dnssec-policy \"%s\";\n", zone.DNS.DNSSECpolicy)
			fmt.Fprintf(includeFile, "    inline-signing yes;\n")
		}
		if len(zone.DNS.ParentalAgents) > 0 {
			fmt.Fprintf(includeFile, "    parental-agents {\n")
			for _, parentalAgent := range zone.DNS.ParentalAgents {
				fmt.Fprintf(includeFile, "        %s;\n", parentalAgent)
			}
			fmt.Fprintf(includeFile, "    };\n")
		}
		if len(zone.DNS.AllowUpdate) > 0 {
			fmt.Fprintf(includeFile, "    allow-update {\n")
			for _, allowUpdate := range zone.DNS.AllowUpdate {
				fmt.Fprintf(includeFile, "        %s;\n", allowUpdate)
			}
			fmt.Fprintf(includeFile, "    };\n")
		}
		if len(zone.DNS.ZoneOptions) > 0 {
			for _, zoneOptions := range zone.DNS.ZoneOptions {
				fmt.Fprintf(includeFile, "        %s;\n", zoneOptions)
			}
		}
		fmt.Fprintf(includeFile, "};\n")

		err = dns.UpdateZone(host, zone, false)
		if err != nil {
			return err
		}

	}
	return nil
}

// Copy zonefiles if changed to destination with new serial number and reload zone
func (dns *DNSManager) UpdateCommit(host *ConfigDNS_HostTemplate) error {
	var reloadAll bool

	slog.Debug("----- DNSManager.UpdateCommit() -----")
	tmpIncludeFile, err := SafeJoin(host.Tmpdir, host.IncludeFile)
	if err != nil {
		return err
	}
	includeFile, err := SafeJoin(host.Configdir, host.IncludeFile)
	if err != nil {
		return err
	}

	equal, err := FilesEqual(tmpIncludeFile, includeFile)
	if err != nil {
		return err
	}
	if !equal {
		slog.Info("Copy file", "source", tmpIncludeFile, "dest", includeFile)
		err = CopyFile(tmpIncludeFile, includeFile)
		if err != nil {
			return err
		}
		slog.Info("named need reload config changed!")
		reloadAll = true
	}
	var host1 *ConfigDNS_HostTemplate
	for _, zone := range dns.P.Zones {
		if host1 == nil {
			host1 = zone.Host
		}
		equal, err := FilesEqual(zone.TmpFile, zone.DstFile)
		if err != nil {
			return err
		}
		if !equal {
			slog.Info("Zone content has changed", "zone", zone.Name)
			err = dns.UpdateZone(host, zone, true)
			if err != nil {
				return err
			}
			slog.Info("Copy file", "source", zone.TmpFile, "dest", zone.DstFile)
			err = CopyFile(zone.TmpFile, zone.DstFile)
			if err != nil {
				return err
			}
			if !reloadAll {
				if err := dns.Reload(zone.Name, zone.Host); err != nil {
					return err
				}
			}
		}
	}
	if reloadAll {
		if host1 == nil {
			host1 = host
		}
		if err := dns.ReloadAll(host1); err != nil {
			return err
		}
	}
	return nil
}
