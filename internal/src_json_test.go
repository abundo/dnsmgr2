package internal

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeJSONRecords(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "records.json")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestSrcJSONLoadBasic(t *testing.T) {
	path := writeJSONRecords(t, `{
  "version": 1,
  "domains": [
    {
      "name": "example.com",
      "records": [
        {"name": "mail", "type": "A", "value": "192.0.2.10"},
        {"name": "@", "type": "MX", "value": "10 mail"},
        {"name": "@", "type": "TXT", "value": "v=spf1 mx -all"},
        {"name": "www", "ttl": 300, "type": "A", "value": "192.0.2.4"}
      ]
    }
  ]
}`)
	dm := testDnsManager("example.com")
	if err := SrcJSONLoad(dm, path); err != nil {
		t.Fatalf("SrcJSONLoad() = %v", err)
	}
	if err := dm.VerifyRecords(); err != nil {
		t.Fatalf("VerifyRecords() = %v", err)
	}

	got := map[string]*Record{}
	for _, r := range (*dm.Zones)[0].Records {
		key := r.Name + "/" + r.Type
		got[key] = r
	}
	if got["mail/A"] == nil || got["mail/A"].Value != "192.0.2.10" {
		t.Errorf("mail A = %#v", got["mail/A"])
	}
	if got["@/MX"] == nil || got["@/MX"].Value != "10 mail" {
		t.Errorf("MX = %#v", got["@/MX"])
	}
	if got["@/TXT"] == nil || got["@/TXT"].Value != `"v=spf1 mx -all"` {
		t.Errorf("TXT = %#v", got["@/TXT"])
	}
	if got["www/A"] == nil || got["www/A"].TTL != 300 {
		t.Errorf("www TTL = %#v", got["www/A"])
	}
}

func TestSrcJSONLoadMACReservation(t *testing.T) {
	path := writeJSONRecords(t, `{
  "domains": [
    {
      "name": "example.com",
      "records": [
        {"name": "test", "type": "A", "value": "192.0.2.4", "mac": "AA-BB-CC-DD-EE-FF"},
        {"name": "mail", "type": "A", "value": "192.0.2.10"}
      ]
    }
  ]
}`)
	dm := testDnsManager("example.com")
	if err := SrcJSONLoad(dm, path); err != nil {
		t.Fatalf("SrcJSONLoad() = %v", err)
	}
	var testRec, mailRec *Record
	for _, r := range (*dm.Zones)[0].Records {
		switch r.Name {
		case "test":
			testRec = r
		case "mail":
			mailRec = r
		}
	}
	if testRec == nil {
		t.Fatal("missing test record")
	}
	if testRec.MAC != "aa:bb:cc:dd:ee:ff" {
		t.Errorf("test MAC = %q", testRec.MAC)
	}
	if mailRec == nil {
		t.Fatal("missing mail record")
	}
	if mailRec.MAC != "" {
		t.Errorf("mail MAC = %q", mailRec.MAC)
	}
}

func TestSrcJSONLoadInvalidMAC(t *testing.T) {
	path := writeJSONRecords(t, `{
  "domains": [
    {
      "name": "example.com",
      "records": [
        {"name": "test", "type": "A", "value": "192.0.2.4", "mac": "not-a-mac"}
      ]
    }
  ]
}`)
	dm := testDnsManager("example.com")
	err := SrcJSONLoad(dm, path)
	if err == nil {
		t.Fatal("expected invalid MAC error")
	}
	if !strings.Contains(err.Error(), "MAC") {
		t.Errorf("error = %v, want MAC", err)
	}
}

func TestSrcJSONLoadTXTDKIMAndQuoted(t *testing.T) {
	path := writeJSONRecords(t, `{
  "domains": [
    {
      "name": "example.com",
      "records": [
        {"name": "mail", "type": "A", "value": "192.0.2.10"},
        {"name": "dkim", "type": "TXT", "value": "v=DKIM1; k=rsa; p=abc"},
        {"name": "@", "type": "TXT", "value": "\"v=spf1 mx -all\""}
      ]
    }
  ]
}`)
	dm := testDnsManager("example.com")
	if err := SrcJSONLoad(dm, path); err != nil {
		t.Fatalf("SrcJSONLoad() = %v", err)
	}
	if err := dm.VerifyRecords(); err != nil {
		t.Fatalf("VerifyRecords() = %v", err)
	}
	var dkim, spf string
	for _, r := range (*dm.Zones)[0].Records {
		if r.Type != "TXT" {
			continue
		}
		switch r.Name {
		case "dkim":
			dkim = r.Value
		case "@":
			spf = r.Value
		}
	}
	if dkim != `"v=DKIM1; k=rsa; p=abc"` {
		t.Errorf("dkim TXT = %q", dkim)
	}
	if spf != `"v=spf1 mx -all"` {
		t.Errorf("spf TXT = %q", spf)
	}
}

func TestSrcJSONLoadReverseOverride(t *testing.T) {
	path := writeJSONRecords(t, `{
  "domains": [
    {
      "name": "example.com",
      "reverse4": false,
      "records": [
        {"name": "a", "type": "A", "value": "192.0.2.4"},
        {"name": "b", "type": "A", "value": "192.0.2.5", "reverse": true}
      ]
    }
  ]
}`)
	dm := testDnsManager("example.com")
	if err := SrcJSONLoad(dm, path); err != nil {
		t.Fatalf("SrcJSONLoad() = %v", err)
	}
	got := map[string]bool{}
	for _, r := range (*dm.Zones)[0].Records {
		got[r.Name] = r.Reverse
	}
	if got["a"] {
		t.Errorf("a reverse = true, want false from domain reverse4")
	}
	if !got["b"] {
		t.Errorf("b reverse = false, want true from record override")
	}
}

func TestSrcJSONLoadUnsupportedVersion(t *testing.T) {
	path := writeJSONRecords(t, `{"version": 2, "domains": []}`)
	dm := testDnsManager("example.com")
	err := SrcJSONLoad(dm, path)
	if err == nil || !strings.Contains(err.Error(), "unsupported version") {
		t.Fatalf("error = %v, want unsupported version", err)
	}
}

func TestSrcJSONLoadMissingFields(t *testing.T) {
	path := writeJSONRecords(t, `{
  "domains": [
    {
      "name": "example.com",
      "records": [
        {"name": "test", "type": "A"}
      ]
    }
  ]
}`)
	dm := testDnsManager("example.com")
	err := SrcJSONLoad(dm, path)
	if err == nil || !strings.Contains(err.Error(), "required") {
		t.Fatalf("error = %v, want required", err)
	}
}

func TestSrcJSONLoadInvalidJSON(t *testing.T) {
	path := writeJSONRecords(t, `{not json`)
	dm := testDnsManager("example.com")
	err := SrcJSONLoad(dm, path)
	if err == nil {
		t.Fatal("expected JSON error")
	}
}

func TestSrcJSONLoadExampleFile(t *testing.T) {
	path := filepath.Join("..", "examples", "records-example.json")
	dm := testDnsManager("example.com")
	if err := SrcJSONLoad(dm, path); err != nil {
		t.Fatalf("SrcJSONLoad(example) = %v", err)
	}
	if err := dm.VerifyRecords(); err != nil {
		t.Fatalf("VerifyRecords() = %v", err)
	}
	var sawMAC bool
	for _, r := range (*dm.Zones)[0].Records {
		if r.Name == "test" && r.MAC == "02:00:00:00:00:04" {
			sawMAC = true
		}
	}
	if !sawMAC {
		t.Fatal("example JSON missing test MAC reservation")
	}
}

func TestFormatTxtRdata(t *testing.T) {
	if got := formatTxtRdata("v=DKIM1; k=rsa; p=abc"); got != `"v=DKIM1; k=rsa; p=abc"` {
		t.Errorf("quote = %q", got)
	}
	in := `"v=spf1 mx -all"`
	if got := formatTxtRdata(in); got != in {
		t.Errorf("leave quoted = %q", got)
	}
	if got := formatTxtRdata(`say "hi"`); got != `"say \"hi\""` {
		t.Errorf("escape = %q", got)
	}
	long := strings.Repeat("a", 256)
	got := formatTxtRdata(long)
	want := `"` + strings.Repeat("a", 255) + `" "a"`
	if got != want {
		t.Errorf("split = %q, want %q", got, want)
	}
}
