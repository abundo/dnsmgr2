package dnsmgr

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/abundo/dnsmgr2/models"
	"golang.org/x/sys/unix"
	"gopkg.in/yaml.v2"
	"gorm.io/gorm"
)

const maxTTL int64 = 2147483647 // RFC 2181: 32-bit TTL, high bit treated as 0

// print structures JSON formatted
func Pprint(data any) {
	s, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return
	}
	fmt.Println(string(s))
}

func ReadConfigFile(filename string, config *ConfigRoot) error {
	data, err := os.ReadFile(filename)
	if err != nil {
		return err
	}
	err = yaml.Unmarshal(data, config)
	return err
}

// LoadConfigFile reads a dnsmgr2 YAML config. Callers such as factum2-dns
// use this instead of reimplementing YAML load.
func LoadConfigFile(filename string) (ConfigRoot, error) {
	var cfg ConfigRoot
	if err := ReadConfigFile(filename, &cfg); err != nil {
		return ConfigRoot{}, err
	}
	return cfg, nil
}

// SetupLogging applies -d / --loglevel to the default slog logger.
// -d forces debug regardless of --loglevel.
func SetupLogging(debug bool, loglevel string) {
	level := slog.LevelInfo
	switch strings.ToLower(strings.TrimSpace(loglevel)) {
	case "error":
		level = slog.LevelError
	case "warning", "warn":
		level = slog.LevelWarn
	case "info", "":
		level = slog.LevelInfo
	case "debug":
		level = slog.LevelDebug
	}
	if debug {
		level = slog.LevelDebug
	}
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level})))
}

// ----- common functions -----

// RunCommand runs a configured command string (e.g. "sudo rndc reload example.com").
// The string is split on whitespace; it is not passed to a shell.
func RunCommand(cmdline string) error {
	cmdline = strings.TrimSpace(cmdline)
	if cmdline == "" {
		return errors.New("empty command")
	}
	parts := strings.Fields(cmdline)
	slog.Info("Running command", "cmd", cmdline)
	cmd := exec.Command(parts[0], parts[1:]...)
	out, err := cmd.CombinedOutput()
	if len(out) > 0 {
		slog.Info("command output", "cmd", cmdline, "output", string(out))
	}
	if err != nil {
		return fmt.Errorf("%s: %w: %s", cmdline, err, strings.TrimSpace(string(out)))
	}
	return nil
}

func GetBoolean(v string) (bool, error) {
	okval := []string{"on", "off", "true", "false", "1", "0", "t", "f", "yes", "no"}
	trueval := []string{"on", "true", "1", "t", "yes"}

	v = strings.ToLower(v)
	if !slices.Contains(okval, v) {
		return false, errors.New("invalid true/false value:" + v)
	}
	return slices.Index(trueval, v) >= 0, nil
}

// GetMACaddress parses a MAC and returns canonical lowercase colon form
// (aa:bb:cc:dd:ee:ff). Accepted input: aa:bb:cc:dd:ee:ff, aa-bb-cc-dd-ee-ff,
// aabb.ccdd.eeff, aabbccddeeff.
func GetMACaddress(v string) (string, error) {
	v = strings.TrimSpace(strings.ToLower(v))
	if v == "" {
		return "", errors.New("empty MAC address")
	}
	var hexChars []byte
	for i := 0; i < len(v); i++ {
		c := v[i]
		switch {
		case c == ':' || c == '-' || c == '.':
			continue
		case (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'):
			hexChars = append(hexChars, c)
		default:
			return "", errors.New("invalid MAC address: " + v)
		}
	}
	if len(hexChars) != 12 {
		return "", errors.New("invalid MAC address: " + v)
	}
	var b strings.Builder
	b.Grow(17)
	for i := 0; i < 12; i += 2 {
		if i > 0 {
			b.WriteByte(':')
		}
		b.Write(hexChars[i : i+2])
	}
	return b.String(), nil
}

// VerifyDnsname checks a DNS owner name or target. "@" is allowed.
// Labels may contain letters, digits, hyphen, underscore (SRV/TLSA), or be "*".
func VerifyDnsname(v string) error {
	v = strings.TrimSpace(v)
	if v == "" {
		return errors.New("DNS name is empty")
	}
	if v == "@" {
		return nil
	}
	if strings.ContainsAny(v, "/\\\t\n\r\x00 ") {
		return fmt.Errorf("invalid DNS name %q", v)
	}
	if len(v) > 254 {
		return fmt.Errorf("DNS name too long: %q", v)
	}
	name := strings.TrimSuffix(v, ".")
	if name == "" {
		return errors.New("DNS name is empty")
	}
	for _, label := range strings.Split(name, ".") {
		if err := verifyDnsLabel(label); err != nil {
			return fmt.Errorf("invalid DNS name %q: %w", v, err)
		}
	}
	return nil
}

func verifyDnsLabel(label string) error {
	if label == "" {
		return errors.New("empty label")
	}
	if len(label) > 63 {
		return errors.New("label longer than 63 characters")
	}
	if label == "*" {
		return nil
	}
	for i := 0; i < len(label); i++ {
		c := label[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '_', c == '-':
		default:
			return fmt.Errorf("invalid character %q in label", rune(c))
		}
	}
	return nil
}

// SafeJoin joins base and a relative name and rejects empty names, absolute
// names, and paths that escape base (after cleaning).
func SafeJoin(base, name string) (string, error) {
	if strings.TrimSpace(name) == "" {
		return "", errors.New("empty path name")
	}
	if filepath.IsAbs(name) {
		return "", fmt.Errorf("path must be relative: %s", name)
	}
	baseAbs, err := filepath.Abs(base)
	if err != nil {
		return "", err
	}
	joined := filepath.Clean(filepath.Join(baseAbs, name))
	if !pathUnderRoot(baseAbs, joined) {
		return "", fmt.Errorf("path %q escapes %s", name, base)
	}
	return joined, nil
}

func pathUnderRoot(root, path string) bool {
	rootAbs, err := filepath.Abs(root)
	if err != nil {
		return false
	}
	pathAbs, err := filepath.Abs(path)
	if err != nil {
		return false
	}
	rel, err := filepath.Rel(filepath.Clean(rootAbs), filepath.Clean(pathAbs))
	if err != nil {
		return false
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator))
}

// CopyFile copies srcpath to dstpath using a same-directory temp file and
// rename so a crash cannot leave a truncated destination.
func CopyFile(srcpath, dstpath string) (err error) {
	r, err := os.Open(srcpath)
	if err != nil {
		return err
	}
	defer r.Close()

	dir := filepath.Dir(dstpath)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".dnsmgr2-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() {
		if err != nil {
			_ = os.Remove(tmpName)
		}
	}()

	if _, err = io.Copy(tmp, r); err != nil {
		_ = tmp.Close()
		return err
	}
	if err = tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err = tmp.Close(); err != nil {
		return err
	}
	if err = os.Chmod(tmpName, 0o644); err != nil {
		return err
	}
	return os.Rename(tmpName, dstpath)
}

func Sha256sum(filename string) ([]byte, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return nil, err
	}
	return h.Sum(nil), nil
}

// FilesEqual reports whether src and dst have the same SHA-256.
// A missing dst is not an error: equal is false (caller should copy).
// Other read errors on either file are returned.
func FilesEqual(src, dst string) (bool, error) {
	a, err := Sha256sum(src)
	if err != nil {
		return false, err
	}
	b, err := Sha256sum(dst)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	return bytes.Equal(a, b), nil
}

// GetSerial returns the YYYYMMDDnn serial for zonename.
// If next is true, the stored serial is incremented and saved.
func GetSerial(db *gorm.DB, zonename string, next bool) (string, error) {
	if db == nil {
		return "", errors.New("database is not open")
	}
	var zone models.Zone

	dateFormat := "20060102"
	t := time.Now()

	res := db.Where("name = ?", zonename).First(&zone)
	if res.Error != nil {
		zone.Name = zonename
		zone.SerialDate = t.Format(dateFormat)
		zone.SerialSeq = 0

		res = db.Save(&zone)
		if res.Error != nil {
			return "", res.Error
		}
	}

	if next {
		if zone.SerialDate < t.Format(dateFormat) {
			zone.SerialDate = t.Format(dateFormat)
			zone.SerialSeq = 0
		} else {
			if zone.SerialSeq >= 99 {
				zone.SerialSeq = 0
				t = t.AddDate(0, 0, 1)
				zone.SerialDate = t.Format(dateFormat)
			} else {
				zone.SerialSeq++
			}
		}

		res = db.Save(&zone)
		if res.Error != nil {
			return "", res.Error
		}
	}

	return fmt.Sprintf("%s%02d", zone.SerialDate, zone.SerialSeq), nil
}

type fileLock struct {
	f *os.File
}

func AcquireLock(lockPath string) (*fileLock, error) {
	if err := os.MkdirAll(filepath.Dir(lockPath), 0o755); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o644)
	if err != nil {
		return nil, err
	}
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("another dnsmgr2 process is running (lock %s): %w", lockPath, err)
	}
	return &fileLock{f: f}, nil
}

func (l *fileLock) Close() error {
	if l == nil || l.f == nil {
		return nil
	}
	_ = unix.Flock(int(l.f.Fd()), unix.LOCK_UN)
	err := l.f.Close()
	l.f = nil
	return err
}

func ReverseIpv4Addr(addr netip.Addr) string {
	abytes := addr.As4()
	slices.Reverse(abytes[:])
	name := netip.AddrFrom4(abytes).String()
	return name
}

func ReverseIpv6Addr(addr netip.Addr) string {
	// Reverse IPv6 address on nibble level
	abytes := addr.As16()
	var tmp strings.Builder
	for src := int8(15); src >= 0; src-- {
		n1 := abytes[src] & 0xf
		n2 := abytes[src] >> 4
		tmp.WriteString(fmt.Sprintf("%x.%x.", n1, n2))
	}
	name := tmp.String()[:63]
	return name
}
