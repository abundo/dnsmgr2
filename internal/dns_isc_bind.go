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
	"strconv"
	"strings"
)

type DNSManagerOpt struct {
	Dbfile     string
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
	fmt.Printf("ISC BIND status: not implemented\n")
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
		zone.SOA = &SOA
	}
	return nil
}

// Write one zonefile, optionally update SOA serial
func (dns *DNSManager) UpdateZone(host *ConfigDNS_HostTemplate, zone *Zone, newSerial bool) error {
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
	format := fmt.Sprintf("%%-35s  %%5s  %%-8s  %%s\n")

	// Write SOA
	serial, err := GetSerial(dns.P.Dbfile, zone.Name, newSerial)
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
		slog.Debug(format, record.Name, TTL, record.Type, record.Value)
		fmt.Fprintf(file, format, record.Name, TTL, record.Type, record.Value)
	}

	file.Close()

	// Check if zone is valid
	cmd := exec.Command("named-checkzone", zone.Name, zone.TmpFile)
	out, err := cmd.CombinedOutput()
	if err != nil {
		slog.Error("named-checkzone", "CombinedOuput", err)
		return err
	}
	if cmd.ProcessState.ExitCode() > 0 {
		fmt.Printf("named-checkzone error: %s\n", out)
	} else {
		slog.Debug("named-checkzone validation ok")
	}
	return nil
}

// Write all zone files
func (dns *DNSManager) Update(host *ConfigDNS_HostTemplate, newSerial bool) error {
	var err error
	slog.Debug("----- DNSManager.Update() -----")

	// ISC BIND include file, with zone definition
	includeFileStr := host.Tmpdir + "/" + host.IncludeFile
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
		zone.DstFile = zone.Host.ZonesDir + "/" + zone.Name
		zone.TmpFile = zone.Host.Tmpdir + "/" + zone.Name

		slog.Info("Creating", "zone", zone.TmpFile)
		fmt.Fprintf(includeFile, "\nzone \"%s\" {\n", zone.Name)
		fmt.Fprintf(includeFile, "    type primary;\n")
		fmt.Fprintf(includeFile, "    file \"%s\";\n", zone.DstFile)
		if zone.DNS.DNSSECpolicy != "" {
			fmt.Fprintf(includeFile, "    dnssec-policy \"%s\";\n", zone.DNS.DNSSECpolicy)
			fmt.Fprintf(includeFile, "    inline-signing yes;\n")
		}
		if len(zone.DNS.ParentalAgents) > 0 {
			fmt.Fprintf(includeFile, "    parental-agents {;\n")
			for _, parentalAgent := range zone.DNS.ParentalAgents {
				fmt.Fprintf(includeFile, "        %s;\n", parentalAgent)
			}
			fmt.Fprintf(includeFile, "    };\n")
		}
		if len(zone.DNS.AllowUpdate) > 0 {
			fmt.Fprintf(includeFile, "    allow-update {;\n")
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
	var err error
	var reloadAll bool

	slog.Debug("----- DNSManager.UpdateCommit() -----")
	tmpIncludeFile := host.Tmpdir + "/" + host.IncludeFile
	includeFile := host.Configdir + "/" + host.IncludeFile

	if !Sha256sumEqual(tmpIncludeFile, includeFile) {
		// configuration has changed, need to reload all. Is this true? check bind documentation
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
		if !Sha256sumEqual(zone.DstFile, zone.TmpFile) {
			// Zone content has changed, recreate zonefile with new serial number
			slog.Info("Zone content has changed", "zone", zone.Name)
			err = dns.UpdateZone(host, zone, true)
			if err != nil {
				return err
			}
			// Copy zone file to correct destionation
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
