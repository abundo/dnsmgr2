package dnsmgr

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v2"
)

// ConfigZoneInclude is the document written into a zone include file.
// Either this mapping (zones: / prefixes: / include:) or a YAML list of
// ConfigZone is accepted.
type ConfigZoneInclude struct {
	Zones    []ConfigZone   `yaml:"zones,omitempty"`
	Prefixes []ConfigPrefix `yaml:"prefixes,omitempty"`
	Include  IncludePaths   `yaml:"include,omitempty"`
}

func (g ConfigDataType) includeOnly() bool {
	return len(g.Include) > 0 &&
		g.HostDnsTemplate == "" &&
		g.HostDhcpTemplate == "" &&
		len(g.Zones) == 0 &&
		len(g.Prefixes) == 0
}

// LoadZoneIncludes reads dnsmgr2 include items. An include-only list
// item (no host templates) is expanded and its zones/prefixes are
// appended to the preceding item. Include files listed on a group that
// already has a host template are appended onto that group. Relative
// paths are resolved against baseDir. Include lists are cleared after a
// successful load so a second call is a no-op.
func LoadZoneIncludes(cfg *ConfigRoot, baseDir string) error {
	if cfg == nil {
		return fmt.Errorf("config is nil")
	}
	out := make(ConfigDataGroups, 0, len(cfg.Dnsmgr2))
	for i := range cfg.Dnsmgr2 {
		g := cfg.Dnsmgr2[i]
		only := g.includeOnly()
		if err := g.loadIncludes(baseDir); err != nil {
			return err
		}
		if only {
			if len(out) == 0 {
				return fmt.Errorf("include must follow a dnsmgr2 entry with host_dns_template or host_dhcp_template")
			}
			prev := &out[len(out)-1]
			prev.Zones = append(prev.Zones, g.Zones...)
			prev.Prefixes = append(prev.Prefixes, g.Prefixes...)
			continue
		}
		out = append(out, g)
	}
	cfg.Dnsmgr2 = out
	return nil
}

func (g *ConfigDataType) loadIncludes(baseDir string) error {
	paths := g.Include
	if len(paths) == 0 {
		return nil
	}
	g.Include = nil
	visited := map[string]struct{}{}
	for _, p := range paths {
		p = strings.TrimSpace(p)
		if p == "" {
			return fmt.Errorf("empty include path")
		}
		if err := loadZoneIncludeFile(g, resolveIncludePath(baseDir, p), visited); err != nil {
			return err
		}
	}
	return nil
}

func resolveIncludePath(baseDir, name string) string {
	if filepath.IsAbs(name) {
		return name
	}
	if strings.TrimSpace(baseDir) == "" {
		return name
	}
	return filepath.Join(baseDir, name)
}

func loadZoneIncludeFile(group *ConfigDataType, path string, visited map[string]struct{}) error {
	abs, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("zone include %s: %w", path, err)
	}
	if _, seen := visited[abs]; seen {
		return fmt.Errorf("zone include cycle: %s", abs)
	}
	visited[abs] = struct{}{}

	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("zone include %s: %w", path, err)
	}
	zones, prefixes, nested, err := parseZoneInclude(data)
	if err != nil {
		return fmt.Errorf("zone include %s: %w", path, err)
	}
	group.Zones = append(group.Zones, zones...)
	group.Prefixes = append(group.Prefixes, prefixes...)
	for _, inc := range nested {
		inc = strings.TrimSpace(inc)
		if inc == "" {
			return fmt.Errorf("empty include path in %s", path)
		}
		next := resolveIncludePath(filepath.Dir(abs), inc)
		if err := loadZoneIncludeFile(group, next, visited); err != nil {
			return err
		}
	}
	return nil
}

func parseZoneInclude(data []byte) ([]ConfigZone, []ConfigPrefix, []string, error) {
	if len(bytes.TrimSpace(data)) == 0 {
		return nil, nil, nil, nil
	}
	var raw interface{}
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil, nil, nil, err
	}
	switch raw.(type) {
	case []interface{}:
		var list []ConfigZone
		if err := yaml.Unmarshal(data, &list); err != nil {
			return nil, nil, nil, err
		}
		return list, nil, nil, nil
	default:
		var doc ConfigZoneInclude
		if err := yaml.Unmarshal(data, &doc); err != nil {
			return nil, nil, nil, err
		}
		return doc.Zones, doc.Prefixes, doc.Include, nil
	}
}
