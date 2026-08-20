package internal

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
	"slices"
	"strings"
	"time"

	"github.com/abundo/dnsmgr2/models"
	"gopkg.in/yaml.v2"
)

// print structures JSON formatted
func Pprint(data any) {
	s, _ := json.MarshalIndent(data, "", "  ")
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

// ----- common functions -----

// RunCommand runs a configured shell-style command string (e.g. "sudo rndc reload example.com").
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

func GetMACaddress(v string) (string, error) {
	return v, nil
}

func VerifyDnsname(v string) error {
	_ = v
	return nil
}

// Copy copies the contents of the file at srcpath to a regular file
// at dstpath. If the file named by dstpath already exists, it is
// truncated. The function does not copy the file mode, file
// permission bits, or file attributes.
func CopyFile(srcpath, dstpath string) (err error) {
	r, err := os.Open(srcpath)
	if err != nil {
		return err
	}
	defer r.Close() // ignore error: file was opened read-only.

	w, err := os.Create(dstpath)
	if err != nil {
		return err
	}

	defer func() {
		// Report the error, if any, from Close, but do so
		// only if there isn't already an outgoing error.
		if c := w.Close(); err == nil {
			err = c
		}
	}()

	_, err = io.Copy(w, r)
	return err
}

// calculate sha256sum of a file
// if file does not exist, or other errors opening file, return nil
func Sha256sum(filename string) []byte {
	f, err := os.Open(filename)
	if err != nil {
		return nil
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return nil
	}
	sum := h.Sum(nil)
	return sum
}

// Compare two files by calculating SHA256 checksums
// returns true if the are equal
func Sha256sumEqual(filename1 string, filename2 string) bool {
	return bytes.Equal(Sha256sum(filename1), Sha256sum(filename2))
}

// Get new serial number
// We use a sqlite database for this, one row per domain
// If next is true, increment serial and save it
func GetSerial(dbfile string, zonename string, next bool) (string, error) {
	var zone models.Zone

	dateFormat := "20060102"
	t := time.Now()

	db, err := ConnectMigrate(dbfile)
	if err != nil {
		return "", err
	}

	// Get current serial
	res := db.Where("name = ?", zonename).First(&zone)
	if res.Error != nil {
		// No serial, create one
		zone.Name = zonename
		zone.SerialDate = t.Format(dateFormat)
		zone.SerialSeq = 0

		res = db.Save(&zone)
		if res.Error != nil {
			return "", res.Error
		}
	}

	if next {
		// Get next serial number

		if zone.SerialDate < t.Format(dateFormat) {
			// Serial date is in the past, create one for today
			zone.SerialDate = t.Format(dateFormat)
			zone.SerialSeq = 0
		} else {
			// Increase current serial
			if zone.SerialSeq >= 99 {
				zone.SerialSeq = 0
				t = t.AddDate(0, 0, 1)
				zone.SerialDate = t.Format(dateFormat)
			} else {
				zone.SerialSeq++
			}
		}

		// Update new serial
		res = db.Save(&zone)
		if res.Error != nil {
			return "", res.Error
		}
	}

	return fmt.Sprintf("%s%02d", zone.SerialDate, zone.SerialSeq), nil
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
