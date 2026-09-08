package internal

import (
	"bufio"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

const maxIncludeDepth = 16

type srcfileState struct {
	domain   string
	forward  bool
	reverse4 bool
	reverse6 bool
	depth    int
	rootDir  string
	seen     map[string]bool
}

// Read all records from the records file
//
// Empty lines and comments starting with # or ; are ignored.
// $INCLUDE paths are relative to the including file and must stay under
// the original source file's directory.

func SrcfileLoad(dm *DnsManager, filename string) error {
	abs, err := filepath.Abs(filename)
	if err != nil {
		return err
	}
	st := &srcfileState{
		forward:  true,
		reverse4: true,
		reverse6: true,
		rootDir:  filepath.Dir(abs),
		seen:     map[string]bool{},
	}
	return srcfileLoad(dm, abs, st)
}

func srcfileLoad(dm *DnsManager, filename string, st *srcfileState) error {
	cleaned := filepath.Clean(filename)
	if st.depth > maxIncludeDepth {
		return fmt.Errorf("$INCLUDE nested too deeply (%s)", cleaned)
	}
	if !pathUnderRoot(st.rootDir, cleaned) {
		return fmt.Errorf("$INCLUDE %s is outside %s", cleaned, st.rootDir)
	}
	if st.seen[cleaned] {
		return fmt.Errorf("$INCLUDE cycle: %s", cleaned)
	}
	st.seen[cleaned] = true
	defer delete(st.seen, cleaned)

	file, err := os.Open(cleaned)
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
			continue
		}
		if strings.HasPrefix(line, "$") {
			tmp := strings.SplitN(line, " ", 2)
			if len(tmp) < 2 {
				return errors.New("unknown directive or syntax: " + line)
			}
			arg := strings.TrimSpace(tmp[1])
			switch tmp[0] {
			case "$DOMAIN":
				err = VerifyDnsname(arg)
				if err != nil {
					return err
				}
				st.domain = arg
				continue
			case "$INCLUDE":
				if arg == "" {
					return errors.New("$INCLUDE path is empty")
				}
				var incPath string
				if filepath.IsAbs(arg) {
					incPath = filepath.Clean(arg)
				} else {
					incPath = filepath.Join(filepath.Dir(cleaned), arg)
				}
				st.depth++
				err = srcfileLoad(dm, incPath, st)
				st.depth--
				if err != nil {
					return err
				}
				continue
			case "$FORWARD":
				st.forward, err = GetBoolean(arg)
				if err != nil {
					return err
				}
				continue
			case "$REVERSE":
				st.reverse4, err = GetBoolean(arg)
				if err != nil {
					return err
				}
				st.reverse6 = st.reverse4
				continue
			case "$REVERSE4":
				st.reverse4, err = GetBoolean(arg)
				if err != nil {
					return err
				}
				continue
			case "$REVERSE6":
				st.reverse6, err = GetBoolean(arg)
				if err != nil {
					return err
				}
				continue
			default:
				return errors.New("unknown directive: " + line)
			}
		}

		mac := ""
		var reverse *bool

		line, args := splitRecordOptions(line)
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
		r.Forward = st.forward

		if r.Name != "@" {
			if err := VerifyDnsname(r.Name); err != nil {
				return err
			}
		}

		if reverse == nil {
			if r.Type == "A" {
				reverse = &st.reverse4
			}
			if r.Type == "AAAA" {
				reverse = &st.reverse6
			}
		}
		if reverse != nil {
			r.Reverse = *reverse
		}
		err = dm.AddForwardRecord(st.domain, r)
		if err != nil {
			return err
		}
	}
	return scanner.Err()
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
