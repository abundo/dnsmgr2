package dnsmgr

import (
	"strings"
	"testing"
)

func TestNormalizeDNSSECPolicies(t *testing.T) {
	got, err := normalizeDNSSECPolicies([]ConfigDNSSECPolicy{
		{
			Name: "lab", KSKLifetime: "P1y", KSKAlgorithm: "ECDSAP256SHA256",
			ZSKLifetime: "30D", ZSKAlgorithm: "ecdsap256sha256",
			PurgeKeys: "365d", SignaturesValidity: "P14D",
			SignaturesValidityDNSKEY: "14d", SignaturesRefresh: "5d",
		},
		{
			Name: "lab", KSKLifetime: "P1Y", KSKAlgorithm: "ecdsap256sha256",
			ZSKLifetime: "30d", ZSKAlgorithm: "ecdsap256sha256",
			PurgeKeys: "365d", SignaturesValidity: "P14D",
			SignaturesValidityDNSKEY: "14d", SignaturesRefresh: "5d",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("policies = %#v", got)
	}
	p := got[0]
	if p.Name != "lab" || p.KSKLifetime != "P1Y" || p.KSKAlgorithm != "ecdsap256sha256" || p.ZSKLifetime != "30d" {
		t.Fatalf("normalized = %#v", p)
	}
	if _, err := normalizeDNSSECPolicies([]ConfigDNSSECPolicy{{Name: "default", KSKAlgorithm: "ecdsap256sha256"}}); err == nil {
		t.Fatal("expected built-in default to be rejected")
	}
	if _, err := normalizeDNSSECPolicies([]ConfigDNSSECPolicy{
		{Name: "lab", KSKAlgorithm: "ecdsap256sha256"},
		{Name: "lab", ZSKAlgorithm: "ecdsap256sha256"},
	}); err == nil {
		t.Fatal("expected conflicting definitions to be rejected")
	}
	if _, err := normalizeDNSSECPolicies([]ConfigDNSSECPolicy{{Name: "lab", KSKLifetime: "P1Y"}}); err == nil {
		t.Fatal("expected lifetime without algorithm to be rejected")
	}
}

func TestWriteDNSSECPolicy(t *testing.T) {
	policies, err := normalizeDNSSECPolicies([]ConfigDNSSECPolicy{{
		Name: "lab", KSKLifetime: "P1y", KSKAlgorithm: "ecdsap256sha256",
		ZSKAlgorithm:      "ecdsap256sha256",
		SignaturesRefresh: "5d", SignaturesValidity: "14d",
		SignaturesValidityDNSKEY: "14d", PurgeKeys: "90d",
	}})
	if err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	if err := writeDNSSECPolicies(&b, policies); err != nil {
		t.Fatal(err)
	}
	text := b.String()
	for _, want := range []string{
		`dnssec-policy "lab" {`,
		"ksk lifetime P1Y algorithm ecdsap256sha256;",
		"zsk algorithm ecdsap256sha256;",
		"purge-keys 90d;",
		"signatures-refresh 5d;",
		"signatures-validity 14d;",
		"signatures-validity-dnskey 14d;",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("missing %q\n%s", want, text)
		}
	}
}

func TestLoadZoneIncludesDNSSECPolicies(t *testing.T) {
	dir := t.TempDir()
	writeInclude(t, dir, "zones.yaml", `
dnssec_policies:
  - name: lab
    ksk_lifetime: P1Y
    ksk_algorithm: ecdsap256sha256
    zsk_lifetime: 30d
    zsk_algorithm: ecdsap256sha256
zones:
  - name: example.com
    type: forward
    dns_template: default_dns
    dnssec_policy: lab
`)
	cfg := ConfigRoot{
		Dnsmgr2: ConfigDataGroups{
			{HostDnsTemplate: "bind"},
			{Include: IncludePaths{"zones.yaml"}},
		},
	}
	if err := LoadZoneIncludes(&cfg, dir); err != nil {
		t.Fatal(err)
	}
	if len(cfg.Dnsmgr2) != 1 {
		t.Fatalf("groups = %#v", cfg.Dnsmgr2)
	}
	g := cfg.Dnsmgr2[0]
	if len(g.DNSSECPolicies) != 1 || g.DNSSECPolicies[0].Name != "lab" || g.DNSSECPolicies[0].KSKLifetime != "P1Y" {
		t.Fatalf("policies = %#v", g.DNSSECPolicies)
	}
	if len(g.Zones) != 1 || g.Zones[0].DNSSECpolicy != "lab" {
		t.Fatalf("zones = %#v", g.Zones)
	}
}
