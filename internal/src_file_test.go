package internal

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseRecordLine(t *testing.T) {
	tests := []struct {
		line  string
		name  string
		ttl   int64
		typ   string
		value string
	}{
		{line: "test A 1.2.3.4", name: "test", typ: "A", value: "1.2.3.4"},
		{line: "test 300 A 1.2.3.4", name: "test", ttl: 300, typ: "A", value: "1.2.3.4"},
		{line: "@ MX 10 mail", name: "@", typ: "MX", value: "10 mail"},
		{line: "@  600  MX  10 mail.example.com.", name: "@", ttl: 600, typ: "MX", value: "10 mail.example.com."},
		{line: `@ TXT "v=spf1 mx -all"`, name: "@", typ: "TXT", value: `"v=spf1 mx -all"`},
		{line: `@ TXT "hello  world"`, name: "@", typ: "TXT", value: `"hello  world"`},
		{line: `_443._tcp.www TLSA 3 1 1 aabbcc`, name: "_443._tcp.www", typ: "TLSA", value: "3 1 1 aabbcc"},
		{line: "host mx 10 mail", name: "host", typ: "MX", value: "10 mail"},
	}
	for _, tt := range tests {
		name, ttl, typ, value, err := parseRecordLine(tt.line)
		if err != nil {
			t.Errorf("parseRecordLine(%q) error = %v", tt.line, err)
			continue
		}
		if name != tt.name || ttl != tt.ttl || typ != tt.typ || value != tt.value {
			t.Errorf("parseRecordLine(%q) = (%q, %d, %q, %q), want (%q, %d, %q, %q)",
				tt.line, name, ttl, typ, value, tt.name, tt.ttl, tt.typ, tt.value)
		}
	}
}

func TestSplitRecordOptionsIgnoresQuotedSemicolon(t *testing.T) {
	record, opts := splitRecordOptions(`@ TXT "v=spf1; include:x" ; reverse=0`)
	if record != `@ TXT "v=spf1; include:x"` {
		t.Errorf("record = %q", record)
	}
	if opts != "reverse=0" {
		t.Errorf("opts = %q", opts)
	}
}

func TestSrcfileLoadMXTLSATXT(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "records")
	content := `$DOMAIN example.com

mail                                    A       192.0.2.10
@                                       MX      10 mail
@                                       TXT     "v=spf1 mx -all"
_443._tcp.www                           TLSA    3 1 1 ` + strings.Repeat("ab", 32) + `
`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	dm := testDnsManager("example.com")
	if err := SrcfileLoad(dm, path); err != nil {
		t.Fatalf("SrcfileLoad() = %v", err)
	}
	if err := dm.VerifyRecords(); err != nil {
		t.Fatalf("VerifyRecords() = %v", err)
	}

	got := map[string]string{}
	for _, r := range (*dm.Zones)[0].Records {
		got[r.Type] = r.Value
	}
	if got["MX"] != "10 mail" {
		t.Errorf("MX value = %q", got["MX"])
	}
	if got["TXT"] != `"v=spf1 mx -all"` {
		t.Errorf("TXT value = %q", got["TXT"])
	}
	if got["TLSA"] != "3 1 1 "+strings.Repeat("ab", 32) {
		t.Errorf("TLSA value = %q", got["TLSA"])
	}
}
