# Port Prowler — Feature Specification

Version: 1.0  
Date: 2025-12-15

Summary
-------
Port Prowler is a Go-based CLI tool that scans a single target (IPv4 or hostname → first IPv4) for port states using TCP connect, UDP, and privileged stealth (SYN) scans. It supports single ports, lists and ranges, runs scans in parallel across ports (worker pool) while running requested scan types sequentially per port, and prints a human-readable table to stdout. Optionally writes the same table to a file atomically. Service and OS detection are opt-in.

High-level constraints
----------------------
- Single target per run (positional): `portprowler [flags] <target>`.
- Target must be an IPv4 address or a hostname that resolves to at least one IPv4 address. If multiple IPv4 addresses are returned, only the first is scanned. If only IPv6 addresses resolve, run fails with a clear error.
- No CIDR, no multiple targets, no IPv6 support in initial version.
- No silent fallbacks for privileged operations: if `-s` requested and privileges/raw sockets unavailable, the tool fails with a clear message.
- Service and OS detection are opt-in flags only.
- Default behaviour is lightweight and fast.

Functional requirements
-----------------------
1. Port selection
   - `-p <spec>` required. Accepts:
     - Single port: `22`
     - Comma-separated: `22,80,443`
     - Range: `1-1024`
     - Mixed: `22,80,8000-8100`
   - Validate ports (1..65535). Invalid spec → clear error and non-zero exit.

2. Scan modes
   - TCP connect (`-tcp`): default when no scan flags provided.
     - Implementation: `net.DialTimeout("tcp", addr, timeout)`.
     - State mapping:
       - connect success → open
       - connection refused → closed
       - timeout/no response → filtered
     - Banner grabbing after successful connect where applicable.
   - UDP (`-udp`):
     - Send small probe or protocol-specific probe (e.g., DNS for 53), wait for response.
     - Application response → open
     - ICMP port-unreachable (if surfaced) → closed
     - No response → filtered (report ambiguity clearly)
   - Stealth (`-s`):
     - SYN scan using raw sockets (requires privileges).
     - Interpret SYN-ACK → open (send RST), RST → closed, no reply → filtered.
     - If privileges unavailable and `-s` requested → fail with explicit error (no fallback).

3. Multiple scan flags behavior
   - If multiple scan flags are provided, run every requested scan type for each port.
   - For a given port the scan types run sequentially (per-port sequential), but ports are distributed to workers and scanned in parallel across workers.
   - Results reported as separate entries per protocol (e.g., `22/tcp`, `22/stealth`, `53/udp`).

4. Service and OS detection (opt-in)
   - Controlled by long flags:
     - `--service-detect` (no short alias)
     - `--os-detect` (no short alias)
   - Both run only for ports determined to be `open`.
   - Service detection:
     - Banner grabbing and lightweight protocol probes (HTTP HEAD on 80, SSH banner, SMTP HELO on 25, DNS query on 53 UDP).
     - Match against small signature DB to identify common services.
     - Output: service name, service banner, detection confidence (high|medium|low).
   - OS detection:
     - Non-privileged best-effort heuristics only (banner text + open-port patterns).
     - Do not use TTL/window or raw-socket fingerprinting.
     - Output: OS guess and confidence (low|medium|high).

5. Concurrency and performance
   - Worker-pool across ports. Default workers: 100 (`-c <num>` configurable).
   - Per-probe timeout default: 1s (`-t <duration>`).
   - Retries: 0 by default (no retries).
   - No exponential backoff in default behavior.

6. Output
   - Default: human-readable table printed to stdout.
     - Columns: TARGET | IP | PORT/PROTO | STATE | SERVICE | INFO
       - INFO includes RTT, confidence, and brief error messages.
   - `-f <file>` writes the same human-readable table to file (overwrite) with atomic write semantics:
     - Write to temp file in same directory → fsync → close → os.Rename(temp, final).
     - On error leave original file unchanged.
   - No automatic format inference. Machine-readable formats (JSON/NDJSON) only via explicit future flag (e.g., `-o`) — not present in initial version.
   - Verbose mode `-v` prints debug/log details (raw banners, timing, decisions).

7. Error handling & exit codes
   - Fatal CLI/config/privilege errors: print clear message and exit non-zero.
   - Per-port network errors: recorded in result INFO and do not abort the whole scan.
   - Suggested exit codes:
     - 0: success (scan completed)
     - 2: usage/CLI error (missing args, malformed -p)
     - 3: privilege/config error (stealth requested but privileges missing)
     - 4: runtime fatal (resolver failure, file IO failure)
   - Prominent legal/ethical warning required in CLI header and README: only scan hosts you own or are authorized to test.

Non-functional requirements
---------------------------
- Portability: support Linux/macOS for basic TCP/UDP scanning; stealth (raw sockets) may be platform-specific — document platforms and require privileges.
- Robustness: proper timeouts, handle network errors gracefully, ensure connections closed promptly to avoid fd leaks.
- Testability: network operations abstracted via Dialer interfaces for unit tests (no real network dependency).
- Performance: default concurrency set to balance speed and resource usage (100 workers).
- Safety: no destructive payloads; tool is reconnaissance-only.

Data model (per-result)
-----------------------
Each scan result entry contains:
- target: original target arg
- ip: resolved IPv4
- port: numeric port
- proto: "tcp" | "udp" | "stealth"
- state: "open" | "closed" | "filtered"
- service: optional (string)
- service_banner: optional (string)
- os_guess: optional (string)
- confidence: optional (low|medium|high)
- rtt_ms: round-trip time in milliseconds (optional)
- error: optional per-port error message

CLI specification
-----------------
Usage:
```
portprowler [flags] <target>
```

Flags:
- -p <ports>            : required port specification (single, list, range, mixed)
- -tcp                  : enable TCP connect scan (default if no scan flags)
- -udp                  : enable UDP scan
- -s                    : enable stealth (SYN) scan — requires privileges; no fallback
- -f <file>             : write table-style output to file (overwrite; atomic)
- --service-detect      : opt-in service detection (only for open ports)
- --os-detect           : opt-in OS detection (only for open ports)
- -c <num>              : worker count (default 100)
- -t <duration>         : per-probe timeout (default 1s), e.g., `500ms`, `2s`
- -v                    : verbose logging

Behavior notes:
- If none of `-tcp`, `-udp`, `-s` are provided, a TCP connect scan is performed.
- If `-s` is provided and raw sockets/privileges are not available, the tool exits with a clear message and non-zero code (no silent fallback).
- If hostname resolves to multiple IPv4 addresses, only the first is used and reported.
- If hostname resolves only to IPv6, the tool exits with an IPv6-not-supported error.

Scan orchestration & sequencing
-------------------------------
- Build list of discrete ports from `-p`.
- Build job list: one job per (port, protocol) pair but ensure per-port scan types execute sequentially; implement by placing scan types in job struct and workers executing scan types in order.
- Start N workers (default 100). Each worker:
  - Pulls a job for a single port
  - For each requested scan type in job.ScanTypes:
    - Run scan with context timeout
    - Record PortResult and emit
    - If open and `--service-detect` enabled → run service detection (synchronous)
    - If open and `--os-detect` enabled → run OS heuristics (synchronous)
- Aggregator collects results and prints table to stdout (and buffers for file write if -f supplied).

Scanner implementations (overview)
----------------------------------
- TCP connect scanner:
  - net.DialTimeout with per-probe timeout.
  - On success, optionally perform banner grab (read up to N bytes).
  - Port-specific lightweight probes for HTTP/SMTP where appropriate.
- UDP scanner:
  - net.DialUDP/send + read with deadline.
  - For well-known ports (53) send protocol-specific probe (DNS).
  - No response → filtered; application response → open; ICMP port-unreachable → closed if surfaced.
- Stealth (SYN) scanner:
  - Requires raw socket privileges. Minimal SYN craft and listen loop to parse replies.
  - On SYN-ACK emit open and send RST to abort; RST → closed; no response → filtered.
  - Privilege check early; if absent and `-s` requested → exit with clear message.

Service detection details
-------------------------
- Trigger: only for `open` results when `--service-detect` is set.
- Method:
  - For TCP: use any banner read during connect; otherwise send small probes appropriate to port and attempt to read banner.
  - For UDP: send small protocol probe (DNS on 53) and parse response.
  - Match banners by substring/regex against built-in signature map to produce service name and confidence.
- Safety: probes are lightweight and designed to avoid state-changing operations.

OS detection details
--------------------
- Trigger: only for `open` results when `--os-detect` is set.
- Method:
  - Banner-based heuristics (e.g., "Windows" in SMB/HTTP banner).
  - Open-port pattern heuristics (e.g., RDP 3389 suggests Windows).
  - Conservative, non-privileged, best-effort guesses with confidence.
- No raw-socket fingerprinting or IP-level heuristics.

Output & file writing
---------------------
- Console table output by default (aligned columns).
- File output `-f` writes the same table to the specified path:
  - Overwrites existing file on success.
  - Uses atomic write: write to temp file in same directory → fsync → close → rename.
  - On failure original file remains unchanged.
- Future machine-readable output formats only via explicit `-o` flag (not in v1).

Testing & quality
-----------------
- Unit tests:
  - Port parser (valid and invalid specs).
  - Resolver (mocked) for hostname→first IPv4.
  - Scanner logic using Dialer interfaces to simulate open/closed/timeout.
  - Service signature matching.
  - Atomic file writer behavior.
- Integration tests:
  - Local TCP servers (net.Listen) and UDP servers for positive/negative flows.
  - Tests for CLI flows (optional) using the compiled binary.
- CI:
  - run `go test ./...`, `go vet`, linters.
- Abstractions:
  - All network IO abstracted via interfaces for deterministic unit tests.

Security, legal & ethics
------------------------
- CLI and README must display a clear legal warning: only scan networks you own or are authorized to test.
- No destructive payloads; tool is reconnaissance-only.
- Stealth scan requires elevated privileges and is explicitly gated.

Operational limits & known limitations
-------------------------------------
- No IPv6 support in initial release.
- No multi-target/CIDR support initially.
- UDP results are inherently ambiguous; reported as filtered when no definitive reply.
- Stealth scan requires privileges and platform support; documented accordingly.

Examples
--------
Terminal:
```
portprowler -p 22,80,443 -tcp example.com
```

Write to file:
```
portprowler -p 1-1024 -tcp -c 200 -t 2s -f results.txt example.com
```

Stealth (must be run privileged):
```
sudo portprowler -p 22,80 -s example.com
```

Open ports with detection:
```
portprowler -p 22,80 --service-detect --os-detect example.com
```

Deliverables (v1)
-----------------
- CLI binary `portprowler` implementing the specified behavior.
- Source tree with scanner, detectors, output and tests.
- README with usage, examples and legal warning.
- Specs and technical documentation.

Change policy
-------------
- Any future features that alter default behavior must be opt-in via explicit flags.
- Backwards-incompatible changes must be documented and released with major-version bump.

End of specification.