# Port Prowler — Project Constitution

Version: 1.0  
Date: 2025-12-15

## Purpose
Port Prowler is a single-target, Go-based CLI utility for port scanning. It provides TCP connect, UDP and privileged stealth scans, optional service and OS detection (opt-in), parallel scanning across ports, and human-readable terminal + file output. It is intentionally lightweight, non-destructive and suitable for safe, authorized testing.

## Scope & Constraints
- Single target per run (positional argument): `portprowler [flags] <target>`.
- Target may be an IPv4 address or a hostname.
  - If hostname resolves to multiple IPv4 addresses, only the first IPv4 address is scanned (and reported).
  - If hostname resolves only to IPv6, fail with a clear error (IPv6 not supported).
- No CIDR, no multiple targets, no IPv6 support in the initial version.
- Service and OS detection are opt-in only.

## Core Principles
- Predictable, explicit behavior: no silent fallbacks for privileged operations.
- Minimal default network noise and fast scans by default.
- Clear, concise terminal output; file output mirrors terminal by default.
- Safe file writes: atomic write to temp → rename; overwrite allowed, never append.

## Scan Modes
- TCP connect scan (`-tcp`): default if no scan flags provided.
  - Implementation: `net.DialTimeout("tcp", addr, timeout)`.
  - States: open (connect success), closed (connection refused), filtered (timeout/no response).
  - Banner grabbing for open TCP ports where applicable.
- UDP scan (`-udp`):
  - Send a small probe (or empty packet) and wait for ICMP port-unreachable → closed.
  - No response after timeout → reported as filtered (open|filtered is ambiguous; use "filtered").
  - Application-level responses (e.g., DNS) treated as open.
- Stealth scan (`-s`):
  - Implemented as SYN scan using raw sockets (requires elevated privileges).
  - If the user requests `-s` and required privileges/raw sockets are not available, the tool MUST fail with a clear error instructing the user to rerun with elevated privileges. No silent fallback to TCP connect.
  - Interpretation: SYN-ACK → open (send RST), RST → closed, no response → filtered.

## Scan Execution Model
- Worker-pool concurrency across ports:
  - Default workers: 100 (configurable via `-c <num>`).
  - Ports are distributed to workers; for each port, requested scan types run sequentially (protocol scans sequential per port), not concurrently.
  - If multiple scan flags are provided (`-tcp`, `-udp`, `-s`), run all specified scan types for each port.
- Results are emitted as separate entries per protocol, e.g.:
  - `22/tcp`, `22/stealth`, `53/udp`.

## CLI Flags (summary)
- -p <ports>           : port spec (single, comma list, ranges; e.g., `22`, `22,80,8000-8100`) — required
- -tcp                 : perform TCP connect scan
- -udp                 : perform UDP scan
- -s                   : perform stealth scan (SYN; privileged)
- -f <file>            : write terminal-style output to file (overwrite; atomic write)
- --service-detect     : enable service detection (opt-in)
- --os-detect          : enable OS detection (opt-in)
- -c <num>             : worker count (default 100)
- -t <duration>        : per-probe timeout (default `1s`)
- -v                   : verbose/logging (debug)
Notes:
- If none of `-tcp`, `-udp`, `-s` are provided, TCP connect scan is used by default.
- `-p` is required and validated; invalid specs produce clear error and non-zero exit.
- The target is required and positional.

## Parsing Ports
- Supported forms: `22`, `22,80,443`, `1-1024`, mixed `22,80,8000-8100`.
- Invalid port specs return an error and exit > 0.

## Service Detection
- Disabled by default; enabled only with `--service-detect`.
- Run only for ports determined to be OPEN.
- Techniques:
  - Banner grabbing (read initial bytes after connect or SYN-ACK).
  - Protocol-specific probes for common ports (HTTP HEAD on 80/8080, SMTP HELO on 25, DNS query on 53 UDP).
  - Signature matching against a compact strings-to-service map.
- Output per open service:
  - `service` (string), `service_banner` (string), `confidence` (high|medium|low).

## OS Detection
- Disabled by default; enabled only with `--os-detect`.
- Run only for ports determined to be OPEN.
- Non-privileged, portable heuristics only:
  - Banner-based inferences (e.g., "Windows" in an SMB banner).
  - Open-port pattern heuristics (common port sets suggesting OS types).
- Always reported as best-effort with confidence (low|medium|high).
- No raw-socket, TTL/window, or platform-specific hacks.

## Timeouts & Retries
- Default per-probe timeout: 1s (`-t 1s`).
- Default retries: 0 (no retries).
- No retries/backoff by default.

## Output & Files
- Terminal: human-friendly table with columns [TARGET, PORT/PROTO, STATE, SERVICE, INFO].
- File: `-f <file>` writes the same table format to the file (overwrite). Write is atomic: write to a temporary file in the same directory then rename.
- No automatic format inference; format remains "table" unless a future `-o` flag is added.
- Existing files are overwritten on success; on failure the original file remains unchanged and an error is reported.

## Error Handling & Privileges
- Stealth scan without privileges → fail early with clear message instructing elevated execution.
- Hostname resolving to IPv6-only → fail with explicit IPv6-not-supported error.
- All invalid inputs or fatal errors produce descriptive messages and non-zero exit codes.
- Per-port network errors are recorded in output/details for that port.

## Testing & Quality
- Unit tests for:
  - Port parser (valid/invalid cases).
  - Scanner behavior with mocked dialers and controlled responses.
  - Service detection signature matching.
  - OS heuristic outputs.
- Integration tests using local test servers for TCP and UDP.
- CI: `go test ./...`, linting and vet checks.

## Deliverables (initial)
- `cmd/portprowler/main.go` — CLI entrypoint and flag parsing.
- `internal/scanner` — tcp.go, udp.go, stealth.go (SYN raw socket code gated by privilege checks).
- `internal/detector` — service.go, os.go (opt-in).
- `pkg/output` — console.go, file.go (atomic write).
- Tests and CI config, README with legal warning and usage examples.

## Legal & Ethics
- CLI and README MUST include an explicit warning: only scan machines/networks you own or are authorized to test.
- Avoid destructive payloads; tool is for reconnaissance only.

## Extensibility (non-breaking)
Future features must be opt-in or behind explicit flags and must not change default behavior:
- Machine-readable outputs (`-o json|ndjson`) — opt-in.
- Retry/backoff policies — opt-in.
- Privileged full OS fingerprinting mode — separate flag and clear privilege requirement.

---
End of Constitution