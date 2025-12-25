# Port Prowler

## Overview

Port Prowler scans a single IPv4 host (or hostname resolving to IPv4) for port states. It supports:
- TCP connect scans (default)
- UDP probes
- Privileged stealth (SYN) scans (requires raw-socket privileges)
- Optional service detection (--service-detect) using banner matching
- Optional OS heuristics (--os-detect) using banners + port patterns
- Human-readable table output to stdout and optional atomic file write (-f)

This tool is intended for authorized testing only. See the Legal / Ethics section below.

## Installation / Build

Requires Go 1.20+.

Build the CLI:

```sh
go build ./...
# or
make build
```

Run directly:

```sh
go run ./port-prowler -p 22,80 -tcp 127.0.0.1
```

## Usage

Synopsis:

```
portprowler [flags] <target>
```

Flags:
  -p <ports>            Required port specification (e.g. 22,80,8000-8100)
  -tcp                  Enable TCP connect scan
  -udp                  Enable UDP scan (best-effort)
  -s                    Enable stealth (SYN) scan (requires privileges; experimental)
  -f <file>             Write output to file (atomic, in result/)
  --service-detect      Enable basic service detection (limited)
  --os-detect           Enable best-effort host OS detection
  -c <num>              Worker count (default 100)
  -t <duration>         Per-probe timeout (default 1s)
  -v                    Verbose logging

Example:

```sh
./portprowler -p 22,80 --service-detect --os-detect 192.168.1.100
```

## Port spec formats

- Single port: `22`
- Comma-separated list: `22,80,443`
- Range: `1-1024`
- Mixed: `22,80,8000-8100`

The parser validates ports 1..65535. Invalid specs produce a clear error.

## Output columns

The table printed to stdout (and to file with `-f`) contains:

- TARGET   : original target arg (hostname or IP)
- IP       : resolved IPv4 address actually scanned
- PORT/PROTO : e.g. `80/tcp`, `53/udp`, `22/stealth`
- STATE    : one of `open`, `closed`, `filtered`
- SERVICE  : detected service name (when `--service-detect` enabled)
- OS       : OS guess (when `--os-detect` enabled)
- CONFIDENCE : confidence for detection (low|medium|high)
- INFO     : RTT in ms or per-port error or notes

Example table:

```
TARGET         IP             PORT/PROTO  STATE     SERVICE  INFO
example.com    93.184.216.34  80/tcp      open      http     rtt=15ms
```

## Examples

TCP scan (default):
```sh
./portprowler -p 22,80 -tcp 127.0.0.1
```

UDP scan:
```sh
./portprowler -p 53 -udp 127.0.0.1
```

Stealth (SYN) scan — requires privileges:
```sh
sudo ./portprowler -p 22,80 -s <TARGET_IP>
```
Note: If `-s` is requested and the process lacks raw-socket privileges, the tool exits with code 3 and an explanatory message. No fallback is performed.

Service + OS detection (opt-in):
```sh
./portprowler -p 22,80 --service-detect --os-detect 192.168.1.100
```

Save same table output to file atomically:
```sh
./portprowler -p 1-1024 -tcp -f results/scan-$(date +%F).txt example.com
```

## Examples script

See `examples/scan-samples.sh` for ready-to-run examples (local safe examples and placeholders).

## Specs & Docs

Specification and implementation plan (in-repo):
- [`specs/constitution.md`](specs/constitution.md)
- [`specs/port-prowler/spec.md`](specs/port-prowler/spec.md)
- [`specs/port-prowler/plan.md`](specs/port-prowler/plan.md)
- [`specs/port-prowler/tasks.md`](specs/port-prowler/tasks.md)

## Legal / Ethics

WARNING: Only scan hosts and networks you own or have explicit permission to test. Unauthorized scanning may be illegal and/or unethical. Use Port Prowler responsibly.

## Contributing & Release

- Run tests: `make test`
- CI runs `go vet` and `go test ./...` (see `.github/workflows/ci.yml`)
- Use `make build` to produce binaries