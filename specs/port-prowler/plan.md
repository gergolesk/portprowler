# Port Prowler — Technical Implementation Plan

Version: 1.0  
Date: 2025-12-15

This document defines the complete technical plan to implement Port Prowler (Go CLI). It follows the Project Constitution, Spec and clarifications.

---

## Project directory structure

portprowler/
- cmd/
  - portprowler/
    - main.go
- internal/
  - scanner/
    - manager.go       // orchestration, job builder
    - tcp.go
    - udp.go
    - stealth.go       // gated by privilege check
  - detector/
    - service.go
    - os.go
- pkg/
  - port/
    - parse.go         // port spec parser
    - types.go         // shared types (PortJob, PortResult)
  - netutil/
    - dialer.go        // Dialer interfaces & test fakes
    - resolver.go      // resolve hostname -> first IPv4
  - output/
    - console.go       // table writer (stdout)
    - file.go          // atomic write
  - sigs/
    - signatures.go    // small service signature DB
- specs/
  - port-prowler/
    - technical-plan.md
- tests/
  - unit/              // unit tests and fakes
  - integration/       // local TCP/UDP test servers
- go.mod
- README.md
- LICENSE

---

## Modules & packages (roles)

- cmd/portprowler: CLI parsing, validation, high-level orchestration.
- internal/scanner: scanning engine (TCP, UDP, Stealth) and manager; not public API.
- internal/detector: service and OS detection code (opt-in).
- pkg/port: parsing ports and shared data types.
- pkg/netutil: abstracted network operations (Dialer interfaces, resolver, privilege checks) for unit testing.
- pkg/output: console + atomic file writing.
- pkg/sigs: signature table used by service detection (small, embeddable map).
- tests: unit/integration suites.

---

## Public interfaces & data types

All packages are internal/public as above. Key exported types live in pkg/port and pkg/netutil for use by main and tests.

1. pkg/port/types.go (exported)
- PortJob
  - Target string        // original target string
  - IP     string        // resolved IPv4
  - Port   uint16
  - ScanTypes []ScanType // ordered list of scan types to run sequentially
- ScanType (string enum) = "tcp", "udp", "stealth"
- PortResult
  - Target string
  - IP string
  - Port uint16
  - Proto string         // "tcp" | "udp" | "stealth"
  - State string         // "open" | "closed" | "filtered"
  - Service string
  - ServiceBanner string
  - OSGuess string
  - Confidence string    // "low" | "medium" | "high" (for detection)
  - Error string         // network or detection error messages
  - RTTMillis int64

2. pkg/netutil/dialer.go
- type TCPDialer interface { DialContext(ctx context.Context, network, addr string) (net.Conn, error) }
- type UDPDialer interface { DialUDP(ctx context.Context, addr *net.UDPAddr) (*net.UDPConn, error) }
- type RawSocket interface { SendSYN(...) / RecvPacket(...) } // minimal interface for stealth impl
- Test fakes implement these interfaces so scanners can be unit tested.

3. internal/scanner.Manager (public within package)
- NewManager(cfg Config, dialers...) *Manager
- Manager.Run(ctx) error
- Manager returns aggregated results (streamed via channel) for output module.

Configuration structure (used by main → manager):
- Target string
- ResolvedIP string
- Ports []uint16
- ScanTypes []ScanType
- Timeout time.Duration (default 1s)
- Workers int (default 100)
- ServiceDetect bool
- OSDetect bool
- OutputFile string
- Verbose bool

---

## Scanner architecture

Principles:
- Concurrency across ports only.
- For each port, requested scan types are executed sequentially in this order: stealth (if requested), tcp, udp — or as ordered by flags (deterministic).
- Each scan type executed for an individual port emits exactly one PortResult (proto-coded) that the output layer prints/stores.

Components:
- Manager: builds port jobs, starts worker pool, aggregates results.
- Worker: receives a PortJob (port + list of ScanTypes), runs each scan type sequentially and emits PortResult for each.
- Scanners:
  - TCP scanner (internal/scanner/tcp.go)
    - Uses net.DialTimeout (via TCPDialer) with ctx deadline.
    - Interprets errors:
      - success => open (optionally banner grab)
      - connection refused => closed
      - context deadline => filtered
      - other errors => filtered with Error
    - Banner grabbing: after successful connect, read up to N bytes with small read deadline; for port-specific probes, send a short probe (HTTP HEAD for 80).
  - UDP scanner (internal/scanner/udp.go)
    - Uses UDPDialer to send small probe and wait read; for some ports (53) send protocol-specific payload (DNS query).
    - If application response received => open.
    - If ICMP port-unreachable observed (often surfaced as read error or syscall err) => closed.
    - No response => filtered.
    - UDP results are fuzzy — report as filtered unless clear application response/closed.
  - Stealth (SYN) scanner (internal/scanner/stealth.go)
    - Requires RawSocket interface (privileged).
    - Minimal SYN implementation: craft IPv4/TCP SYN, send, listen for reply within timeout.
    - Interpret reply:
      - SYN-ACK => open (send RST), RST => closed, no reply => filtered.
    - Privilege gating: Manager checks privilege via netutil.IsPrivilegedRawSocketAvailable(); if unavailable and user requested -s => Manager returns fatal error (no silent fallback).
    - Implementation note: use gopacket or raw syscall; keep dependency optional. Provide minimal raw socket helper; abstract via RawSocket interface to allow stubbing in tests.

RTT measurement: measure elapsed time around the probe and set RTTMillis in result.

---

## Worker pool design

Constraints from spec:
- Default workers: 100 (-c configurable)
- Each job is a single port with list of scan types to run sequentially.
- Concurrency: N workers pull from jobChan; results are sent to resultsChan.

Design:
- jobChan := make(chan PortJob, jobBuf) — buffer = min(len(ports), workers*2)
- resultsChan := make(chan PortResult, resultBuf)
- Start workers: for i := 0; i < workers; i++ { go worker(ctx, jobChan, resultsChan) }
- Each worker:
  - For each ScanType in job.ScanTypes:
    - create ctx with timeout
    - call scanner for that scan type
    - emit PortResult to resultsChan
    - if ServiceDetect && State == "open" -> call detector.service (synchronously) and enrich result
    - if OSDetect && State == "open" -> call detector.os (synchronously) and enrich result
- Aggregator: main collects results from resultsChan until all jobs complete and workers stopped.
- Cancellation: top-level context used to propagate user cancellation (Ctrl+C). Workers should check ctx regularly.

Job building:
- Parse -p ports => unique []uint16 sorted ascending.
- For each port create PortJob{Target, IP, Port, ScanTypes}
- ScanTypes ordering: follow CLI order if supplied else default order of ["tcp"].

Backpressure & resource limits:
- Limit number of simultaneous open connections per worker (implicit, one at a time).
- If system fd exhaustion detected, Manager reduces concurrency or exits with clear error. For v1, document instead of auto-scaling.

---

## Service detection flow (opt-in --service-detect)

Scope:
- Run only for ports with state == "open".
- Conservative probes, per-port, executed synchronously by the worker after the successful probe.

Steps:
1. If service detection enabled and result.State == "open":
   - If proto == tcp:
     - If banner present from connect step, use it.
     - Else send protocol-specific lightweight probe:
       - port 80/8080/8000 -> "HEAD / HTTP/1.0\r\nHost: example\r\n\r\n"
       - port 22 -> read banner (SSH sends it)
       - port 25 -> "HELO example\r\n"
       - fallback: attempt single Read with deadline to capture any banner
   - If proto == udp:
     - For 53 send a DNS query; for other ports, attempt to read with small timeout.
2. Parse captured banner text (first N bytes).
3. Match against signatures in pkg/sigs/signatures.go:
   - signatures map[string]{service, confidence, hint}
   - Matching done by substring or regexp rules (keep small).
4. Populate result.Service, result.ServiceBanner and result.Confidence (high/medium/low).
5. Return enriched result to resultsChan for output.

Notes:
- Detection should respect timeout budget for the port scan (use remaining time).
- No retries here (retries are disabled by default).

---

## OS detection flow (opt-in --os-detect)

Scope:
- Non-privileged, best-effort heuristics only.
- Run only for ports where service detection is enabled and result.State == "open" OR when --os-detect explicitly set (still gated on open ports).

Heuristics:
1. Banner-based:
   - If banner contains "Windows" or "Microsoft" or SMB hints -> guess "Windows" (confidence medium/high depending on match).
   - If banner contains "Ubuntu" "Debian" "Linux" -> guess "Linux".
   - HTTP server headers (Server: nginx/Apache) + known distro markers => adjust confidence.
2. Port-pattern heuristics:
   - If 3389 open -> likely Windows (RDP).
   - If 135/139/445 -> Windows.
   - If 22 + common Linux services (80/443/3306) -> guess Linux.
   - If only 1900/UPnP patterns -> likely embedded device (router) -> "embedded" low confidence.
3. Result:
   - Populate result.OSGuess and result.Confidence ("low|medium|high") and attach to the first open port result (or attach to each open port's result; both acceptable—choose to attach to each open port result for simplicity).

Notes:
- Heuristics are intentionally conservative and must be documented as "best-effort".
- Avoid extraction of TTL/window/other IP-level fields.

---

## Output formatting & file writing

Terminal output (default):
- Human-readable table printed to stdout.
- Columns: TARGET | IP | PORT/PROTO | STATE | SERVICE | INFO (RTT, confidence, error)
- Use text/tabwriter to align columns.
- Verbose (-v) enables augmenting INFO with raw banners, timings, and decision logs.

File output (-f <file>):
- Writes same human-readable table (not JSON) by default.
- Overwrite mode: replace existing file on success.
- Atomic write:
  - Create temp file in same directory: os.CreateTemp(dir, "portprowler-*.tmp")
  - Write content, call File.Sync(), close.
  - os.Rename(tempPath, finalPath).
  - On any error: remove temp file and return error; leave original file unchanged.
- If file path invalid or permission error -> exit non-zero with descriptive message.

Future: machine-readable formats (json/ndjson) may be added behind -o flag; not in v1.

---

## Error handling rules

Principles:
- Fail-fast on invalid CLI args or fatal config errors (missing target, missing -p ports, stealth requested without privilege, target resolves only to IPv6).
- All fatal errors surface clear, actionable messages and exit with non-zero code.
- Per-port non-fatal network errors are encapsulated in PortResult.Error and printed in INFO column; they do not abort the scan.
- Logging:
  - Default: minimal user-facing messages + table.
  - -v: detailed debug logs (internal decisions, raw banners, timings).
- Exit codes:
  - 0: success (scan completed; per-port problems allowed)
  - 2: usage/CLI error (missing args, invalid port spec)
  - 3: privilege/config error (stealth requested but not allowed)
  - 4: runtime fatal error (IO, resolver failure)
- Privilege errors when -s requested must be explicit and non-ambiguous.

---

## Privilege checks for stealth mode

- Early check in main/manager:
  - If -s requested:
    - Call netutil.CanOpenRawSocket() which:
      - Attempts to create a raw socket in a safe, ephemeral manner OR checks os.Geteuid() == 0 on Unix.
      - Returns (ok bool, err error).
    - If ok == false: print precise error:
      "Stealth scan (-s) requires raw socket privileges. Rerun as root/with CAP_NET_RAW or remove -s to use TCP connect. No fallback will be attempted."
    - Exit with code 3.
- If ok == true: continue and construct RawSocket implementation for stealth.go.
- RawSocket implementation should be wrapped behind build tags or runtime guards where platform support differs; document platforms supported (Linux recommended; test on Linux).

---

## Build & testing strategy

Build:
- Use go modules. Keep third-party deps minimal; consider using gopacket only behind a build tag if needed for stealth.
- go build ./cmd/portprowler

Testing:
1. Unit tests:
   - pkg/port: parse.go — parse ranges, lists, invalid inputs.
   - pkg/netutil: resolver (mock net.LookupIP), TCP/UDP dialer fakes.
   - internal/scanner: use injected dialer fakes to simulate open/closed/timeout conditions for TCP and UDP; verify emitted PortResult state & RTT.
   - internal/detector: service signature matching logic.
   - pkg/output: atomic file write tests (use temp dir).
2. Integration tests:
   - Spawn local net.Listen TCP listeners on ephemeral ports for positive open tests; close for closed tests.
   - UDP integration: simple UDP server (listen and reply) and a "no response" case.
   - Test CLI flows using os/exec to run built binary against local servers (optional).
3. CI:
   - GitHub Actions workflow:
     - go test ./...
     - go vet, golangci-lint (optional)
     - run unit tests; integration tests which require network must run in CI environment with allowed ports.
4. Test fakes:
   - Dialers must be interface-based to permit deterministic unit tests. Avoid reliance on the real network for unit tests.

Test coverage & metrics:
- Aim for >70% unit coverage on core pkg/port, internal/scanner and pkg/netutil.

---

## Implementation roadmap (short-term milestones)

1. Minimal CLI + port parser + resolver (1-2 days)
   - Validate flags, positional target, -p parsing, first-IPv4 resolver, error cases.
   - Unit tests for parser/resolver.

2. Manager + worker pool + TCP scanner + console output (2-3 days)
   - Implement Manager.Run, worker goroutines, TCP scanner, table printing.
   - Integration tests with local TCP server.

3. UDP scanner + detection opt-in hooks (1 day)
   - Implement UDP scanner with fuzzy semantics and tests.

4. Stealth skeleton + privilege check (1-2 days)
   - Implement privilege gating and minimal raw socket check; if privileged implement simple SYN send/recv or integrate gopacket behind a build tag.

5. Service detection + signatures (1-2 days)
   - Implement banner grabs and signatures map; tests.

6. OS detection heuristics (0.5-1 day)
   - Implement conservative heuristics and tests.

7. Output file atomic write + CLI polish + docs + CI (1-2 days)

---

## Risks & mitigations

- Raw socket complexity and cross-platform differences:
  - Mitigate: require privilege and gate code; document supported platforms; optionally use gopacket behind a build tag.
- UDP ambiguity:
  - Mitigate: clearly label UDP results as "filtered" when ambiguous and document behaviour.
- Resource exhaustion (FDs) with large worker counts:
  - Mitigate: default 100 workers, document kernel limits; future autoscaling as enhancement.
- Legal/ethical misuse:
  - Mitigate: prominent README/CLI warnings and require explicit flags for potentially intrusive features.

---

## Deliverables (v1)

- Working CLI binary implementing TCP connect, UDP, and privileged stealth scanning (stealth only when run with privileges).
- Port parser and worker-pool concurrency across ports.
- Optional service and OS detection via explicit flags.
- Human-readable terminal output; atomic file output via -f.
- Unit and integration tests with CI pipeline.

---

End of technical plan.