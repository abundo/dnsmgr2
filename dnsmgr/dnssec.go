package dnsmgr

import (
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"
)

// BIND's built-in policy. A custom block with this name is rejected by named.
const builtinDNSSECPolicy = "default"

var (
	dnssecPolicyNameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$`)
	dnssecAlgorithmRe  = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9]{0,31}$`)
	dnssecTTLRe        = regexp.MustCompile(`(?i)^[0-9]+[smhdw]$`)
	dnssecISORe        = regexp.MustCompile(`(?i)^P(?:[0-9]+Y)?(?:[0-9]+M)?(?:[0-9]+W)?(?:[0-9]+D)?(?:T(?:[0-9]+H)?(?:[0-9]+M)?(?:[0-9]+S)?)?$`)
	dnssecBareRe       = regexp.MustCompile(`^[0-9]+$`)
)

func bindPolicyName(name string) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return "", nil
	}
	if !dnssecPolicyNameRe.MatchString(name) {
		return "", fmt.Errorf("invalid dnssec-policy name %q", name)
	}
	return name, nil
}

func normalizeDNSSECDuration(raw string) (string, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "", nil
	}
	if strings.EqualFold(s, "unlimited") {
		return "unlimited", nil
	}
	if dnssecBareRe.MatchString(s) {
		return s, nil
	}
	if dnssecTTLRe.MatchString(s) {
		return strings.ToLower(s), nil
	}
	if dnssecISORe.MatchString(s) {
		u := strings.ToUpper(s)
		if u != "P" && !strings.HasSuffix(u, "T") {
			return u, nil
		}
	}
	return "", fmt.Errorf("invalid DNSSEC duration %q", raw)
}

func normalizeDNSSECAlgorithm(raw string) (string, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "", nil
	}
	if !dnssecAlgorithmRe.MatchString(s) {
		return "", fmt.Errorf("invalid DNSSEC algorithm %q", raw)
	}
	return strings.ToLower(s), nil
}

func normalizeDNSSECPolicy(in ConfigDNSSECPolicy) (ConfigDNSSECPolicy, error) {
	name, err := bindPolicyName(in.Name)
	if err != nil {
		return ConfigDNSSECPolicy{}, err
	}
	if name == "" {
		return ConfigDNSSECPolicy{}, fmt.Errorf("dnssec-policy name is empty")
	}
	if strings.EqualFold(name, builtinDNSSECPolicy) {
		return ConfigDNSSECPolicy{}, fmt.Errorf("dnssec-policy %q is built into BIND and cannot be redefined", name)
	}
	out := ConfigDNSSECPolicy{Name: name}
	fields := []struct {
		src string
		dst *string
	}{
		{in.KSKLifetime, &out.KSKLifetime},
		{in.ZSKLifetime, &out.ZSKLifetime},
		{in.PurgeKeys, &out.PurgeKeys},
		{in.SignaturesValidity, &out.SignaturesValidity},
		{in.SignaturesValidityDNSKEY, &out.SignaturesValidityDNSKEY},
		{in.SignaturesRefresh, &out.SignaturesRefresh},
	}
	for _, f := range fields {
		v, err := normalizeDNSSECDuration(f.src)
		if err != nil {
			return ConfigDNSSECPolicy{}, fmt.Errorf("dnssec-policy %s: %w", name, err)
		}
		*f.dst = v
	}
	out.KSKAlgorithm, err = normalizeDNSSECAlgorithm(in.KSKAlgorithm)
	if err != nil {
		return ConfigDNSSECPolicy{}, fmt.Errorf("dnssec-policy %s: %w", name, err)
	}
	out.ZSKAlgorithm, err = normalizeDNSSECAlgorithm(in.ZSKAlgorithm)
	if err != nil {
		return ConfigDNSSECPolicy{}, fmt.Errorf("dnssec-policy %s: %w", name, err)
	}
	if out.KSKLifetime != "" && out.KSKAlgorithm == "" {
		return ConfigDNSSECPolicy{}, fmt.Errorf("dnssec-policy %s: KSK lifetime requires an algorithm", name)
	}
	if out.ZSKLifetime != "" && out.ZSKAlgorithm == "" {
		return ConfigDNSSECPolicy{}, fmt.Errorf("dnssec-policy %s: ZSK lifetime requires an algorithm", name)
	}
	return out, nil
}

func sameDNSSECPolicy(a, b ConfigDNSSECPolicy) bool {
	return a == b
}

// normalizeDNSSECPolicies checks policy blocks and drops exact duplicates.
// Two blocks with the same name and different timings are an error.
func normalizeDNSSECPolicies(in []ConfigDNSSECPolicy) ([]ConfigDNSSECPolicy, error) {
	if len(in) == 0 {
		return nil, nil
	}
	byName := make(map[string]ConfigDNSSECPolicy, len(in))
	names := make([]string, 0, len(in))
	for _, raw := range in {
		p, err := normalizeDNSSECPolicy(raw)
		if err != nil {
			return nil, err
		}
		if prev, ok := byName[p.Name]; ok {
			if !sameDNSSECPolicy(prev, p) {
				return nil, fmt.Errorf("dnssec-policy %s is defined more than once", p.Name)
			}
			continue
		}
		byName[p.Name] = p
		names = append(names, p.Name)
	}
	sort.Strings(names)
	out := make([]ConfigDNSSECPolicy, 0, len(names))
	for _, name := range names {
		out = append(out, byName[name])
	}
	return out, nil
}

func collectDNSSECPolicies(groups ConfigDataGroups) ([]ConfigDNSSECPolicy, error) {
	var all []ConfigDNSSECPolicy
	for _, g := range groups {
		all = append(all, g.DNSSECPolicies...)
	}
	return normalizeDNSSECPolicies(all)
}

func writeDNSSECPolicies(w io.Writer, policies []ConfigDNSSECPolicy) error {
	policies, err := normalizeDNSSECPolicies(policies)
	if err != nil {
		return err
	}
	if len(policies) == 0 {
		return nil
	}
	fmt.Fprintf(w, "\n// DNSSEC policies\n")
	for _, p := range policies {
		if err := writeDNSSECPolicy(w, p); err != nil {
			return err
		}
	}
	return nil
}

func writeDNSSECPolicy(w io.Writer, p ConfigDNSSECPolicy) error {
	name, err := bindPolicyName(p.Name)
	if err != nil {
		return err
	}
	if name == "" {
		return fmt.Errorf("dnssec-policy name is empty")
	}
	fmt.Fprintf(w, "dnssec-policy \"%s\" {\n", name)
	if p.KSKAlgorithm != "" || p.ZSKAlgorithm != "" {
		fmt.Fprintf(w, "    keys {\n")
		if err := writeDNSSECKey(w, "ksk", p.KSKLifetime, p.KSKAlgorithm); err != nil {
			return err
		}
		if err := writeDNSSECKey(w, "zsk", p.ZSKLifetime, p.ZSKAlgorithm); err != nil {
			return err
		}
		fmt.Fprintf(w, "    };\n")
	}
	lines := []struct {
		stmt string
		val  string
	}{
		{"purge-keys", p.PurgeKeys},
		{"signatures-refresh", p.SignaturesRefresh},
		{"signatures-validity", p.SignaturesValidity},
		{"signatures-validity-dnskey", p.SignaturesValidityDNSKEY},
	}
	for _, line := range lines {
		if line.val == "" {
			continue
		}
		fmt.Fprintf(w, "    %s %s;\n", line.stmt, line.val)
	}
	fmt.Fprintf(w, "};\n")
	return nil
}

func writeDNSSECKey(w io.Writer, role, lifetime, algorithm string) error {
	if algorithm == "" {
		return nil
	}
	if lifetime == "" {
		fmt.Fprintf(w, "        %s algorithm %s;\n", role, algorithm)
		return nil
	}
	fmt.Fprintf(w, "        %s lifetime %s algorithm %s;\n", role, lifetime, algorithm)
	return nil
}
