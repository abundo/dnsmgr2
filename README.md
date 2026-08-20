# dnsmgr2

Tool to manage ISC BIND from a text records file.

It writes forward and reverse zone files, keeps SOA serial numbers in a
sqlite3 database, and reloads BIND when a zone changes.

## Installation

Requires BIND's `named-checkzone` on `PATH` (Debian/Ubuntu: `bind9-utils`).
`sync` writes under `/etc/bind` and `/var/lib/bind`, so run it as root.

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

## Configuration

See `examples/dnsmgr2-example.yaml`. The main pieces:

- `sources` — records file (`type: file`)
- `dns.host_templates` — BIND paths and reload/restart commands
- `dns.soa_templates` — SOA values
- `dns.zone_templates` — default TTL, NS records, and which SOA template
  to use
- `dnsmgr2` — which host template to use, and the zones to manage
  (`forward`, `reverse4`, `reverse6`)

Each zone names a **zone** template (`dns_template`). That template names
an SOA template.

## Records file

See `examples/records-example`. Empty lines and comments starting with `#`
or `;` are ignored.

    $DOMAIN example.com

    test                                    A       192.0.2.4
    mail                                    A       192.0.2.10
    @                                       MX      10 mail
    @                                       TXT     "v=spf1 mx -all"

Directives:

- `$DOMAIN` — current forward zone
- `$INCLUDE` — read another records file
- `$FORWARD` / `$REVERSE` / `$REVERSE4` / `$REVERSE6` — `on`/`off` (also
  `true`/`false`, `1`/`0`, `yes`/`no`)

A line is `name [ttl] type value`. Optional TTL sits between the name and
the type. Supported types include A, AAAA, MX, TXT and TLSA. A and AAAA
records also get a PTR in a matching reverse zone unless you add
`; reverse=0`.

## Commands

    dnsmgr2 sync          # write zone files and reload BIND
    dnsmgr2 load          # load records and print them
    dnsmgr2 show-config   # print the resolved configuration
    dnsmgr2 restart       # run the host template restart command

Global flags: `-d` (debug), `-l` / `--loglevel` (`error`, `warning`,
`info`, `debug`), `-c` / `--config-file`.

## Daily use

Edit `/etc/dnsmgr2/records`, then:

    sudo dnsmgr2 sync

## Development

See [DEV.md](DEV.md).
