package cmdbase

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/GiGurra/boa/pkg/boa"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	old := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stderr = w
	fn()
	_ = w.Close()
	os.Stderr = old
	var buf bytes.Buffer
	if _, err := io.Copy(&buf, r); err != nil {
		t.Fatal(err)
	}
	_ = r.Close()
	return buf.String()
}

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	fn()
	_ = w.Close()
	os.Stdout = old
	var buf bytes.Buffer
	if _, err := io.Copy(&buf, r); err != nil {
		t.Fatal(err)
	}
	_ = r.Close()
	return buf.String()
}

func failingCmd(rawArgs []string) boa.CmdT[boa.NoParams] {
	return boa.CmdT[boa.NoParams]{
		Use:     "testcli",
		RawArgs: rawArgs,
		SubCmds: boa.SubCmds(
			boa.CmdT[boa.NoParams]{
				Use:   "boom",
				Short: "fail on purpose",
				RunFuncE: func(p *boa.NoParams, cmd *cobra.Command, args []string) error {
					return fmt.Errorf("kaboom")
				},
			},
		),
	}
}

func TestRun_RuntimeErrorDoesNotPrintUsage(t *testing.T) {
	oldExit := osExit
	t.Cleanup(func() { osExit = oldExit })
	exitCode := 0
	osExit = func(code int) { exitCode = code }

	stderr := captureStderr(t, func() {
		Run(failingCmd([]string{"boom"}))
	})

	if exitCode != 1 {
		t.Fatalf("exit code = %d, want 1", exitCode)
	}
	if !strings.Contains(stderr, "Error: kaboom") {
		t.Fatalf("stderr = %q, want Error: kaboom", stderr)
	}
	if strings.Contains(stderr, "Usage:") || strings.Contains(stderr, "Available Commands") {
		t.Fatalf("stderr dumped help on runtime error: %q", stderr)
	}
}

func TestRun_UserInputErrorDoesNotPrintUsage(t *testing.T) {
	oldExit := osExit
	t.Cleanup(func() { osExit = oldExit })
	exitCode := 0
	osExit = func(code int) { exitCode = code }

	stderr := captureStderr(t, func() {
		Run(failingCmd([]string{"boom", "--no-such-flag"}))
	})

	if exitCode != 1 {
		t.Fatalf("exit code = %d, want 1", exitCode)
	}
	if !strings.Contains(stderr, "Error:") {
		t.Fatalf("stderr = %q, want Error:", stderr)
	}
	if strings.Contains(stderr, "Usage:") || strings.Contains(stderr, "Available Commands") {
		t.Fatalf("stderr dumped help on user input error: %q", stderr)
	}
}

func TestRun_HelpStillPrints(t *testing.T) {
	oldExit := osExit
	t.Cleanup(func() { osExit = oldExit })
	osExit = func(code int) {
		t.Fatalf("os.Exit(%d) called for --help", code)
	}

	stdout := captureStdout(t, func() {
		Run(failingCmd([]string{"--help"}))
	})

	if !strings.Contains(stdout, "Available Commands") {
		t.Fatalf("stdout = %q, want help text", stdout)
	}
}

func TestParamsLoadYAMLWithoutGlobalDHCPDNSServers(t *testing.T) {
	boa.RegisterConfigFormat(".yaml", yaml.Unmarshal)
	dir := t.TempDir()
	path := filepath.Join(dir, "dnsmgr2.yaml")
	const body = `
dbfile: /tmp/dnsmgr2.sqlite
sources:
  - type: json
    name: /tmp/records
destinations:
  - type: dhcp_isc_kea
    name: isc_kea
dhcp:
  domain_name: lab.example
  host_templates:
    isc_kea:
      type: isc_kea
      ipv4:
        enable: true
        configdir: /etc/kea
        includefile: kea-dhcp4.dnsmgr2.json
        tmpdir: /tmp
        cmd_restart: "true"
dnsmgr2:
  - host_dhcp_template: isc_kea
    prefixes:
      - name: 192.0.2.0/24
        dns_servers:
          - 192.0.2.53
`
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}

	var loaded *Params
	cmd := boa.CmdT[Params]{
		Use:     "load",
		RawArgs: []string{"--config-file", path},
		RunFuncE: func(p *Params, cmd *cobra.Command, args []string) error {
			loaded = p
			return nil
		},
	}
	if err := cmd.ToCobra().Execute(); err != nil {
		t.Fatalf("load yaml without dhcp.dns_servers: %v", err)
	}
	if loaded == nil {
		t.Fatal("params not loaded")
	}
	if loaded.Config.DHCP.DomainName != "lab.example" {
		t.Errorf("domain_name = %q", loaded.Config.DHCP.DomainName)
	}
	if len(loaded.Config.DHCP.DNSServers) != 0 {
		t.Errorf("dns_servers = %#v, want empty", loaded.Config.DHCP.DNSServers)
	}
	if len(loaded.Config.Dnsmgr2) != 1 || len(loaded.Config.Dnsmgr2[0].Prefixes) != 1 {
		t.Errorf("prefixes = %#v", loaded.Config.Dnsmgr2)
	}
}

func TestParamsLoadYAMLWithoutDHCPSection(t *testing.T) {
	boa.RegisterConfigFormat(".yaml", yaml.Unmarshal)
	dir := t.TempDir()
	path := filepath.Join(dir, "dnsmgr2.yaml")
	const body = `
dbfile: /tmp/dnsmgr2.sqlite
sources:
  - type: json
    name: /tmp/records
destinations:
  - type: dns_isc_bind
    name: isc_bind
dns:
  host_templates:
    isc_bind:
      type: isc_bind
      configdir: /etc/bind
      includefile: named.conf.dnsmgr2
      zonesdir: /var/lib/bind
      zonesfile: "{zone}"
      tmpdir: /tmp
dnsmgr2:
  - host_dns_template: isc_bind
    zones:
      - name: lab.example
        type: forward
        dns_template: default_dns
`
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}

	cmd := boa.CmdT[Params]{
		Use:     "load",
		RawArgs: []string{"--config-file", path},
		RunFuncE: func(p *Params, cmd *cobra.Command, args []string) error {
			return nil
		},
	}
	if err := cmd.ToCobra().Execute(); err != nil {
		t.Fatalf("load yaml without dhcp section: %v", err)
	}
}
