# Development

Assumes the code is checked out in `~/code/dnsmgr2`. `go.mod` targets Go
1.25.

## Checkout

    cd ~/code
    git clone https://github.com/abundo/dnsmgr2
    cd dnsmgr2
    go mod tidy

## Build

    make

Writes `bin/dnsmgr2`. Install to `/usr/bin` (the Makefile runs `sudo`):

    make install

## Tests

    go test ./...
    go vet ./...

GitHub Actions runs `go vet`, `go test`, `make`, and a GoReleaser snapshot
on every push to `main` and on pull requests
(`.github/workflows/ci.yml`).

## Release

Releases are built with [GoReleaser](https://goreleaser.com/) (pure Go,
`CGO_ENABLED=0`) and published to GitHub when a `v*` tag is pushed
(`.github/workflows/release.yml`). Tests must pass first.

    git tag -a v0.1.0 -m "v0.1.0"
    git push origin v0.1.0

Local dry-run (writes `dist/`, does not publish):

    goreleaser check
    make snapshot

## Project layout

- `cmd/dnsmgr2/dnsmgr2.go` — CLI (`load`, `sync`, `show-config`, `restart`,
  `status`)
- `cmd/cmd_base.go` — shared flags (`-c` / `--config-file`, `-d`,
  `-l` / `--loglevel`); config defaults to `/etc/dnsmgr2/dnsmgr2.yaml`
- `internal/` — records file parser, zone/serial handling, ISC BIND and
  ISC Kea drivers
- `models/` — sqlite `Zone` row (SOA serial date + sequence)
- `examples/` — sample YAML config and records file

`status` is not implemented yet.

## Local run

    go run ./cmd/dnsmgr2/dnsmgr2.go show-config -c examples/dnsmgr2-example.yaml
    go run ./cmd/dnsmgr2/dnsmgr2.go load -c /etc/dnsmgr2/dnsmgr2.yaml
