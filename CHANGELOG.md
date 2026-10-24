# Changelog

The major changes in each release. A release's notes on GitHub are its section
here (`dev/release-notes.sh`); the full list is `git log <previous tag>..<tag>`.

## v1.2.3

### Changed

- The Debian package installs `examples/apparmor-usr.bin.dnsmgr2` as
  `/etc/apparmor.d/usr.bin.dnsmgr2`.

### Fixed

- Kea syntax checks write their stub in `/etc/kea` and run as that directory's
  owner. Packaged `kea-dhcp4` and `kea-dhcp6` can only read `/etc/kea`, and
  the directory is often mode `0750` owned by `_kea`.

## v1.2.2

### New

- DNSSEC policies from the zone include are written into `named.conf`.

## v1.2.1

### New

- Extra zone and prefix lists can live in YAML include files.

## v1.2.0

### New

- ISC Kea DHCP. `sync` writes subnet includes (pools and host reservations
  from A/AAAA records with `mac=`), checks them with `kea-dhcp4 -t` and
  `kea-dhcp6 -t`, and restarts Kea when the file changes.
- A JSON records source (`sources[].type: json`) alongside the text file.
- `status` runs each host template `cmd_status` when set, otherwise reports
  whether the generated BIND and Kea files exist.
- The library is importable as `github.com/abundo/dnsmgr2/dnsmgr`.

### Changed

- Kea output is a JSON array of subnets, included from the operator's Kea
  config. Interfaces, the lease database, and timers stay in that file.
  Global `domain_name` and `dns_servers` apply per subnet, and a prefix can
  set its own `dns_servers`.
- `dhcp.dns_servers` is optional when prefixes supply their servers.
- Zone and Kea paths stay inside the configured directories. `$INCLUDE` is
  relative to the including file and must stay under the records directory.
  Sync holds an exclusive lock and replaces files by renaming in the same
  directory.
- SOA serials reuse one sqlite connection.
- A missing reverse zone is logged at debug when the PTR is skipped.
- Go module dependencies are updated.

### Fixed

- BIND `allow-update` and `parental-agents` syntax, IPv4 `/8` reverse zone
  names, PTR owner names, and the SOA rname.
- Validation of DNS names, SRV, SSHFP, and RFC 2181 TTLs.
- A failed zone update includes the `named-checkzone` output.
- A failed command no longer prints the cobra usage text.
- The example records include glue for in-zone nameservers.

## v1.1.0

### Changed

- The license is GPL-3.0-or-later. The `.deb` package includes the license
  text.

## v1.0.0

### New

- First tagged release. Generates BIND zone files from a records file, keeps
  SOA serials in sqlite, and reloads BIND when a zone changes.
- GitHub Actions runs vet, tests, the build, and a GoReleaser snapshot. A
  `v*` tag publishes Linux binaries and `.deb` packages.
