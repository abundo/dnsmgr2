# dnsmgr2

[![ci](https://github.com/abundo/dnsmgr2/actions/workflows/ci.yml/badge.svg)](https://github.com/abundo/dnsmgr2/actions/workflows/ci.yml)

Tool to manage ISC BIND and ISC Kea from a records file (text or JSON).

It writes forward and reverse zone files, keeps SOA serial numbers in a
sqlite3 database, and reloads BIND when a zone changes. When DHCP is
configured it writes Kea DHCPv4/DHCPv6 config (subnets, pools, and host
reservations) and restarts Kea when that config changes.

## Installation

Requires BIND's `named-checkzone` on `PATH` (Debian/Ubuntu: `bind9-utils`).
If DHCP is enabled and `kea-dhcp4` / `kea-dhcp6` are on `PATH`, `sync`
also runs `kea-dhcp4 -t` / `kea-dhcp6 -t` on the generated config.
`sync` writes under `/etc/bind`, `/var/lib/bind`, and (when DHCP is
configured) `/etc/kea`, so run it as root.

Pre-built Linux binaries and `.deb` packages are on the
[GitHub Releases](https://github.com/abundo/dnsmgr2/releases) page.

From source, requires Go 1.25 and `make`:

    git clone https://github.com/abundo/dnsmgr2
    cd dnsmgr2
    make
    make install

`make install` copies the binary to `/usr/bin/dnsmgr2`.

    sudo mkdir -p /etc/dnsmgr2 /var/lib/dnsmgr2
    sudo cp examples/dnsmgr2-example.yaml /etc/dnsmgr2/dnsmgr2.yaml
    sudo cp examples/records-example /etc/dnsmgr2/records

The config file defaults to `/etc/dnsmgr2/dnsmgr2.yaml`. Override with
`-c` / `--config-file` on any command. Do not use tabs in the YAML file.

Edit the config and records for your zones, then generate BIND files:

    sudo dnsmgr2 sync

The first sync creates `/etc/bind/named.conf.dnsmgr2` and the zone files
under `/var/lib/bind`. BIND does not load them yet, so the reload step may
fail; that is expected.

Once, add this include to `/etc/bind/named.conf` after the other include
lines:

    include "/etc/bind/named.conf.dnsmgr2";

Then:

    sudo named-checkconf
    sudo systemctl restart named.service

Later syncs update only changed zones and reload them with `rndc`.

When `host_dhcp_template` is set, `sync` writes a complete Kea JSON
config (the host template `includefile`, typically `/etc/kea/kea-dhcp4.conf`)
and restarts Kea if it changed. That file is overwritten on each change,
the same way zone files are. By default Kea is configured to listen on
all interfaces (`*`); set `interfaces` on the IPv4/IPv6 host template to
restrict that.

## Configuration

See `examples/dnsmgr2-example.yaml`. The main pieces:

- `sources` — records file (`type: file` text, or `type: json` for factum2)
- `dns.host_templates` — BIND paths and reload/restart commands
- `dns.soa_templates` — SOA values (`rname` is a domain-name, e.g.
  `support.example.com.`, not an email address)
- `dns.zone_templates` — default TTL, NS records, and which SOA template
  to use
- `dhcp.domain_name` / `dhcp.dns_servers` — global DHCP options
- `dhcp.host_templates` — Kea paths, optional `interfaces`, and
  restart/status commands (`ipv4` / `ipv6`)
- `dnsmgr2` — which host templates to use, DHCP prefixes, and the zones
  to manage (`forward`, `reverse4`, `reverse6`)

Each zone names a **zone** template (`dns_template`). That template names
an SOA template.

Each DHCP prefix is a CIDR (`name: 192.0.2.0/24`). Optional `range` is
the dynamic pool (`192.0.2.100-192.0.2.200`). `gateway` defaults to the
first usable address in the prefix (network + 1). `subnet_mask` defaults
to the mask implied by the prefix length. Optional `dns_servers` overrides
the global `dhcp.dns_servers` for that subnet.

## Records file

See `examples/records-example`. Empty lines and comments starting with `#`
or `;` are ignored.

    $DOMAIN example.com

    ns1                                     A       192.0.2.53
    ns2                                     A       192.0.2.54
    test                                    A       192.0.2.4
    mail                                    A       192.0.2.10
    @                                       MX      10 mail
    @                                       TXT     "v=spf1 mx -all"

Directives:

- `$DOMAIN` — current forward zone
- `$INCLUDE` — read another records file (path is relative to the
  including file and must stay under that file's directory)
- `$FORWARD` / `$REVERSE` / `$REVERSE4` / `$REVERSE6` — `on`/`off` (also
  `true`/`false`, `1`/`0`, `yes`/`no`)

A line is `name [ttl] type value`. Optional TTL sits between the name and
the type. Supported types include A, AAAA, MX, TXT and TLSA. A and AAAA
records also get a PTR in a matching reverse zone unless you add
`; reverse=0`. Reverse zones in the config must cover those addresses;
otherwise the PTR is skipped and a warning is logged.

If an A or AAAA line ends with `; mac=<mac address>`, Kea gets a host
reservation for that address. MAC forms `aa:bb:cc:dd:ee:ff`,
`aa-bb-cc-dd-ee-ff`, `aabb.ccdd.eeff`, and `aabbccddeeff` are accepted.

    test                                    A       192.0.2.4 ; mac=02:00:00:00:00:04

If a nameserver in the zone template is inside the zone (for example
`ns1.example.com` in `example.com`), it must have an A or AAAA record.
BIND's `named-checkzone` rejects the zone otherwise.

## JSON records file

`sources[].type: json` is the machine transfer format (`factum2-dns`
writes it). See `examples/records-example.json`. TXT `value` is the
unquoted string; dnsmgr2 quotes it when writing BIND zone files. DHCP
reservations are a `mac` field on A/AAAA records, not a comment.

    sources:
        - type: json
          name: /etc/dnsmgr2/records

    {
      "version": 1,
      "domains": [
        {
          "name": "example.com",
          "records": [
            {"name": "test", "type": "A", "value": "192.0.2.4", "mac": "02:00:00:00:00:04"},
            {"name": "@", "type": "TXT", "value": "v=spf1 mx -all"}
          ]
        }
      ]
    }

Optional per domain: `forward`, `reverse4`, `reverse6` (default true).
Optional per record: `ttl`, `reverse`. Unknown `version` values are
rejected; omitted version is 1.

Keep `type: file` for the human-edited text format above.

## Commands

    dnsmgr2 sync          # write zone files and Kea config; reload BIND / restart Kea
    dnsmgr2 load          # load records and print them
    dnsmgr2 show-config   # print the resolved configuration
    dnsmgr2 restart       # run the host template restart command
    dnsmgr2 status        # run cmd_status if set, otherwise report whether dest files exist

Global flags: `-d` (debug), `-l` / `--loglevel` (`error`, `warning`,
`info`, `debug`), `-c` / `--config-file`. `-d` forces debug regardless of
`--loglevel`.

## Daily use

Edit `/etc/dnsmgr2/records`, then:

    sudo dnsmgr2 sync

## Security

`sync` is a local admin tool, not a network service. Run it as root (or
with write access to BIND/Kea paths and permission to run the configured
commands). Anyone who can edit the YAML config or the records file can
change DNS/DHCP data and cause dnsmgr2 to exec the host-template
commands (`rndc`, `systemctl`, …). Those command strings are split on
whitespace and are not passed to a shell.

`$INCLUDE` cannot read files outside the original records file's
directory. Zone and include paths are rejected if they escape their
configured directories. `sync` takes an exclusive lock next to `dbfile`
so two processes cannot rewrite configs at once.

Generated files are installed with a same-directory temp file plus
rename. `named-checkzone` must succeed before a zone is installed. If
`kea-dhcp4` / `kea-dhcp6` are not on `PATH`, Kea config is still written
but not syntax-checked (a warning is logged).

## Development

See [DEV.md](DEV.md).

## License

[GPL-3.0-or-later](LICENSE). Copyright (c) 2026 Anders Löwinger.
