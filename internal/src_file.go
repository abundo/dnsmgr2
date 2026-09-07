package internal

import (
	"bufio"
	"errors"
	"log/slog"
	"os"
	"strconv"
	"strings"
)

// Read all records from the records file
//
// dm: pointer to dnsmgr
// filename: file to read
//
// Empty lines and comments starting with # or ; are ignored
//
// recursive function, to handle $INCLUDE to other files

func SrcfileLoad(dm *DnsManager, filename string) error {
	var err error

	var domain string
	var forward bool = true
	var reverse4 bool = true
	var reverse6 bool = true

	var args string
	var mac string
	var reverse *bool

	file, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	var line string
	for scanner.Scan() {
		line = scanner.Text()
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			// ignore comment
			continue
		}
		if strings.HasPrefix(line, "$") {
			// directive
			tmp := strings.SplitN(line, " ", 2)
			if len(tmp) < 2 {
				return errors.New("unknown directive or syntax: " + line)
			}
			switch tmp[0] {
			case "$DOMAIN":
				err = VerifyDnsname(tmp[1])
				if err != nil {
					return err
				}
				domain = tmp[1]
				continue
			case "$INCLUDE":
				// should domain, forward/reverse follow to new file?
				err = SrcfileLoad(dm, tmp[1])
				if err != nil {
					return err
				}
				continue
			case "$FORWARD":
				forward, err = GetBoolean(tmp[1])
				if err != nil {
					return err
				}
				continue
			case "$REVERSE":
				reverse4, err = GetBoolean(tmp[1])
				if err != nil {
					return err
				}
				reverse6 = reverse4
				continue
			case "$REVERSE4":
				reverse4, err = GetBoolean(tmp[1])
				if err != nil {
					return err
				}
				continue
			case "$REVERSE6":
				reverse6, err = GetBoolean(tmp[1])
				if err != nil {
					return err
				}
				continue
			default:
				return errors.New("unknown directive: " + line)
			}
		}

		// Check if there is options after record
		// ; key=val key=val...
		//
		//  key mac,     value = xxxx.xxxx.xxxx
		//  key reverse, value = [0|1]
		//
		// ';' inside a quoted TXT value is not an option separator.

		mac = ""
		reverse = nil

		line, args = splitRecordOptions(line)
		if args != "" {
			tmp := strings.Fields(args)
			for _, e := range tmp {
				parts := strings.SplitN(e, "=", 2)
				if len(parts) != 2 {
					return errors.New("unknown record options: " + e)
				}
				switch parts[0] {
				case "mac":
					mac, err = GetMACaddress(parts[1])
					if err != nil {
						return err
					}
				case "reverse":
					tmp, err := GetBoolean(parts[1])
					if err != nil {
						return err
					}
					reverse = &tmp
				default:
					return errors.New("unknown record options: " + e)
				}
			}
		}
		slog.Debug(line)

		name, ttl, typ, value, err := parseRecordLine(line)
		if err != nil {
			return err
		}

		r := new(Record)
		r.Name = name
		r.TTL = ttl
		r.Type = typ
		r.Value = value
		r.MAC = mac
		r.Forward = forward

		if r.Name != "@" {
			err := VerifyDnsname(r.Name)
			if err != nil {
				return err
			}
		}

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
		err = dm.AddForwardRecord(domain, r)
		if err != nil {
			return err
		}
	}
	return scanner.Err()
}

func SrcfileStatus(dm *DnsManager) error {
	slog.Debug("source-file-status")
	for _, source := range dm.C.Destinations {
		if source.Type != "file" {
			return errors.New("incorrect source file type:" + source.Type)
		}
		if _, err := os.Stat(source.Name); errors.Is(err, os.ErrNotExist) {
			return errors.New("source file does not exist" + source.Name)
		}
		slog.Debug("source-file-status-valid", "type", source.Type, "path", source.Name)
	}
	return nil
}

// splitRecordOptions splits "record ; key=val..." while ignoring ';' inside quotes.
func splitRecordOptions(line string) (recordLine, options string) {
	inQuote := false
	escaped := false
	for i := 0; i < len(line); i++ {
		c := line[i]
		if escaped {
			escaped = false
			continue
		}
		if inQuote && c == '\\' {
			escaped = true
			continue
		}
		if c == '"' {
			inQuote = !inQuote
			continue
		}
		if c == ';' && !inQuote {
			return strings.TrimSpace(line[:i]), strings.TrimSpace(line[i+1:])
		}
	}
	return strings.TrimSpace(line), ""
}

// parseRecordLine reads name, optional TTL, type and the remaining value.
// The value keeps original spacing so quoted TXT strings stay intact.
func parseRecordLine(line string) (name string, ttl int64, typ string, value string, err error) {
	name, rest, err := nextToken(line)
	if err != nil {
		return "", 0, "", "", errors.New("unknown format, too few values: " + line)
	}
	tok, rest2, err := nextToken(rest)
	if err != nil {
		return "", 0, "", "", errors.New("unknown format, too few values: " + line)
	}
	if n, e := strconv.ParseInt(tok, 10, 64); e == nil {
		ttl = n
		typ, rest, err = nextToken(rest2)
		if err != nil {
			return "", 0, "", "", errors.New("unknown format, too few values: " + line)
		}
	} else {
		typ = tok
		rest = rest2
	}
	typ = strings.ToUpper(typ)
	value = strings.TrimSpace(rest)
	if typ == "" || value == "" {
		return "", 0, "", "", errors.New("unknown format, too few values: " + line)
	}
	return name, ttl, typ, value, nil
}

func nextToken(s string) (token, rest string, err error) {
	i := 0
	for i < len(s) && (s[i] == ' ' || s[i] == '\t') {
		i++
	}
	if i >= len(s) {
		return "", "", errors.New("no token")
	}
	start := i
	for i < len(s) && s[i] != ' ' && s[i] != '\t' {
		i++
	}
	return s[start:i], s[i:], nil
}
