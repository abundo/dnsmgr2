package dnsmgr

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"unicode/utf8"
)

// JSON records file written by factum2-dns (sources[].type: json).
// Version 1 is the current transfer format. Omitted version is treated as 1.
type recordsJSON struct {
	Version int                 `json:"version"`
	Domains []recordsJSONDomain `json:"domains"`
}

type recordsJSONDomain struct {
	Name     string              `json:"name"`
	Forward  *bool               `json:"forward"`
	Reverse4 *bool               `json:"reverse4"`
	Reverse6 *bool               `json:"reverse6"`
	Records  []recordsJSONRecord `json:"records"`
}

type recordsJSONRecord struct {
	Name    string `json:"name"`
	TTL     int64  `json:"ttl"`
	Type    string `json:"type"`
	Value   string `json:"value"`
	MAC     string `json:"mac"`
	Reverse *bool  `json:"reverse"`
}

const recordsJSONVersion = 1

func SrcJSONLoad(dm *DnsManager, filename string) error {
	data, err := os.ReadFile(filename)
	if err != nil {
		return err
	}
	var doc recordsJSON
	if err := json.Unmarshal(data, &doc); err != nil {
		return fmt.Errorf("json records %s: %w", filename, err)
	}
	if doc.Version != 0 && doc.Version != recordsJSONVersion {
		return fmt.Errorf("json records %s: unsupported version %d", filename, doc.Version)
	}
	for di, domain := range doc.Domains {
		if err := loadJSONDomain(dm, domain, di); err != nil {
			return fmt.Errorf("json records %s: %w", filename, err)
		}
	}
	return nil
}

func loadJSONDomain(dm *DnsManager, domain recordsJSONDomain, di int) error {
	name := strings.TrimSpace(domain.Name)
	if name == "" {
		return fmt.Errorf("domains[%d]: name is required", di)
	}
	if err := VerifyDnsname(name); err != nil {
		return fmt.Errorf("domains[%d]: %w", di, err)
	}

	forward := true
	reverse4 := true
	reverse6 := true
	if domain.Forward != nil {
		forward = *domain.Forward
	}
	if domain.Reverse4 != nil {
		reverse4 = *domain.Reverse4
	}
	if domain.Reverse6 != nil {
		reverse6 = *domain.Reverse6
	}

	for ri, rec := range domain.Records {
		if err := loadJSONRecord(dm, name, rec, forward, reverse4, reverse6); err != nil {
			return fmt.Errorf("domains[%d] %s records[%d]: %w", di, name, ri, err)
		}
	}
	return nil
}

func loadJSONRecord(dm *DnsManager, domain string, rec recordsJSONRecord, forward, reverse4, reverse6 bool) error {
	owner := strings.TrimSpace(rec.Name)
	typ := strings.ToUpper(strings.TrimSpace(rec.Type))
	value := strings.TrimSpace(rec.Value)
	if owner == "" || typ == "" || value == "" {
		return fmt.Errorf("name, type and value are required")
	}
	if rec.TTL < 0 {
		return fmt.Errorf("ttl must be >= 0")
	}

	if typ == "TXT" {
		value = formatTxtRdata(value)
	}

	mac := ""
	if raw := strings.TrimSpace(rec.MAC); raw != "" {
		var err error
		mac, err = GetMACaddress(raw)
		if err != nil {
			return err
		}
	}

	r := new(Record)
	r.Name = owner
	r.TTL = rec.TTL
	r.Type = typ
	r.Value = value
	r.MAC = mac
	r.Forward = forward

	if r.Name != "@" {
		if err := VerifyDnsname(r.Name); err != nil {
			return err
		}
	}

	reverse := rec.Reverse
	if reverse == nil {
		if r.Type == "A" {
			reverse = &reverse4
		}
		if r.Type == "AAAA" {
			reverse = &reverse6
		}
	}
	if reverse != nil {
		r.Reverse = *reverse
	}
	return dm.AddForwardRecord(domain, r)
}

// formatTxtRdata quotes TXT rdata for BIND zone files. Unquoted values
// (typical in the JSON transfer format) are quoted and split at 255 bytes.
// Already-quoted values are left as-is.
func formatTxtRdata(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return `""`
	}
	if strings.HasPrefix(value, `"`) {
		return value
	}
	var chunks []string
	var current strings.Builder
	currentBytes := 0
	for _, r := range value {
		n := utf8.RuneLen(r)
		if n < 0 {
			n = 1
		}
		if currentBytes+n > 255 && current.Len() > 0 {
			chunks = append(chunks, quoteTxtString(current.String()))
			current.Reset()
			currentBytes = 0
		}
		current.WriteRune(r)
		currentBytes += n
	}
	chunks = append(chunks, quoteTxtString(current.String()))
	return strings.Join(chunks, " ")
}

func quoteTxtString(s string) string {
	var b strings.Builder
	b.Grow(len(s) + 2)
	b.WriteByte('"')
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '\\' || c == '"' {
			b.WriteByte('\\')
		}
		b.WriteByte(c)
	}
	b.WriteByte('"')
	return b.String()
}
