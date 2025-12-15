# Port Prowler — Implementation Task Breakdown

Sources: specs/constitution.md, specs/port-prowler/spec.md, specs/port-prowler/technical-plan.md

This file lists ordered, small, testable tasks grouped into milestones that implement the Port Prowler project. Each task includes a short acceptance criteria.

---

Milestone 1 — Project scaffold & CLI basics
- 1.1 Create repository layout and go.mod
  - Create directories: cmd/portprowler, pkg/port, pkg/netutil, pkg/output, pkg/sigs, internal/scanner, internal/detector, specs/, tests/
  - Acceptance: `go list ./...` succeeds, repo compiles (empty main).
- 1.2 Implement CLI skeleton (cmd/portprowler/main.go)
  - Parse flags: -p, -tcp, -udp, -s, -f, --service-detect, --os-detect, -c, -t, -v
  - Enforce positional target argument.
  - Acceptance: Running `portprowler` without args prints usage and exit code 2.
- 1.3 Implement target resolver (pkg/netutil/resolver.go)
  - Resolve hostname -> first IPv4; error on IPv6-only.
  - Acceptance: Unit tests for IPv4, hostname with multiple A records (first used), and IPv6-only failure.
- 1.4 Implement port parser (pkg/port/parse.go)
  - Support single, comma lists, ranges, mixed; validate 1..65535
  - Acceptance: Unit tests for valid and invalid specs.

Milestone 2 — Manager, job model and worker pool
- 2.1 Define data types (pkg/port/types.go)
  - PortJob, PortResult, ScanType enum, Config struct
  - Acceptance: Types compile and are documented.
- 2.2 Implement Manager skeleton (internal/scanner/manager.go)
  - Build jobs from ports and scan flags; expose NewManager and Run(ctx)
  - Acceptance: Manager builds expected number of jobs for sample input.
- 2.3 Implement worker pool orchestration
  - jobChan, resultsChan, start/stop workers, graceful shutdown on context cancel
  - Acceptance: Workers consume jobs and results are aggregated; test with mocked workers.
- 2.4 CLI integration: wire main -> manager.Run and print basic progress
  - Acceptance: `portprowler -p 22 127.0.0.1` runs Manager and exits cleanly (no scans yet).

Milestone 3 — TCP connect scanner + console output
- 3.1 Implement TCP scanner (internal/scanner/tcp.go)
  - Use net.DialTimeout; map success/refused/timeout -> open/closed/filtered
  - Measure RTT; close connections; optional banner read
  - Acceptance: Unit tests with injected TCPDialer simulate open/closed/timeout and verify PortResult fields.
- 3.2 Implement console table writer (pkg/output/console.go)
  - Pretty-print aligned table to stdout; include TARGET, IP, PORT/PROTO, STATE, SERVICE, INFO
  - Acceptance: Table output format test, ensure column alignment.
- 3.3 Integrate TCP scanner into Manager workers
  - Workers call tcp scanner per job and send results to resultsChan
  - Acceptance: End-to-end run against local test server returns `open` for listening port and table shows it.
- 3.4 Add -v verbose logging support
  - Acceptance: `-v` prints debug lines (timings, decisions).

Milestone 4 — UDP scanner and result semantics
- 4.1 Implement UDP scanner (internal/scanner/udp.go)
  - Send small probe or empty packet; for port 53 send DNS query; wait read with deadline
  - Map responses -> open; ICMP-unreachable -> closed (if surfaced); no response -> filtered
  - Acceptance: Unit tests with mocked UDPDialer; integration test with local UDP echo/DNS.
- 4.2 Integrate UDP jobs into Manager
  - Acceptance: `-udp` scan returns expected results in table for test server.

Milestone 5 — Service detection hooks & simple signatures
- 5.1 Create signatures map (pkg/sigs/signatures.go)
  - Small map of substrings -> service name and confidence (SSH, HTTP, nginx, OpenSSH, etc.)
  - Acceptance: Unit tests for lookups.
- 5.2 Implement service detection interface (internal/detector/service.go)
  - Accept PortResult (open) and connection/buffered banner; return enriched PortResult
  - Port-specific probes: HTTP HEAD, SMTP HELO, DNS query for UDP 53
  - Acceptance: Unit tests using banner strings and verifying service detection outputs.
- 5.3 Wire service detection into workers (only when --service-detect)
  - Run synchronously after open result; respect remaining timeout budget
  - Acceptance: `--service-detect` populates SERVICE and SERVICE_BANNER fields on open ports in integration tests.

Milestone 6 — OS detection heuristics
- 6.1 Implement OS heuristic engine (internal/detector/os.go)
  - Banner-based rules + port-pattern rules (3389 → Windows, 22+80+3306 → Linux, etc.)
  - Provide confidence levels
  - Acceptance: Unit tests for common banner/port combos.
- 6.2 Integrate OS detection into worker flow (only when --os-detect)
  - Run only for open ports and after service detection if both enabled
  - Acceptance: `--os-detect` attaches OS_GUESS and CONFIDENCE to open-port results.

Milestone 7 — Stealth (SYN) scan skeleton & privilege checks
- 7.1 Implement privilege check utility (pkg/netutil/privilege.go)
  - netutil.CanOpenRawSocket() -> bool, err (use os.Geteuid or attempt raw socket creation)
  - Acceptance: Unit tests (mock os.Geteuid where feasible).
- 7.2 Implement stealth code scaffold (internal/scanner/stealth.go)
  - Provide RawSocket interface; implement privileged SYN send/receive for Linux (basic)
  - For initial delivery, implement minimal behavior or mock; but gate behind privilege check
  - Acceptance: If `-s` requested and privilege check fails, program exits with error code 3 and message; test verifies behavior.
- 7.3 Integrate stealth jobs into Manager
  - Ensure per-port sequential execution semantics preserved
  - Acceptance: With privileges, SYN scan produces expected result for test environment (if feasible) or accept simulated unit test via stubbed RawSocket.

Milestone 8 — File output, atomic write, and logging
- 8.1 Implement atomic file writer (pkg/output/file.go)
  - Write to temp in same dir, fsync, close, rename; on error clean up and preserve original
  - Acceptance: Unit tests in temp dir verify overwrite on success and original preserved on simulated failure.
- 8.2 Wire `-f` flag output buffer and write at scan completion
  - Acceptance: `-f results.txt` creates file with same table content as stdout.
- 8.3 Improve logging and error message consistency
  - Standardize error messages and exit codes
  - Acceptance: Manual review + tests for exit codes on known failure modes.

Milestone 9 — Tests, CI and QA
- 9.1 Unit tests for all components
  - Port parser, resolver, TCP/UDP scanners (with fakes), detectors, output writer
  - Acceptance: `go test ./...` passes locally.
- 9.2 Integration test suite
  - Local TCP listeners and UDP servers; CLI invocation tests (optional)
  - Acceptance: Integration tests pass in CI environment that permits ephemeral listen ports.
- 9.3 CI pipeline
  - GitHub Actions: run `go test ./...`, `go vet`, linters
  - Acceptance: PRs trigger CI and pass.
- 9.4 Test coverage targets and flaky test handling
  - Acceptance: Reasonable coverage on core packages; flaky tests marked and stabilized.

Milestone 10 — Documentation, examples and release
- 10.1 Write README with usage, examples and legal warning
  - Include examples from spec, usage of flags, and note about privileges.
  - Acceptance: README contains warning and at least three usage examples.
- 10.2 Add docs/constitution.md, specs/port-prowler/spec.md and technical-plan.md (ensure paths)
  - Acceptance: Files present and referenced in README.
- 10.3 Add example scripts (examples/scan-samples.sh)
  - Acceptance: Scripts demonstrate common use-cases.
- 10.4 Create release build script and Makefile targets
  - Targets: build, test, lint, ci
  - Acceptance: `make build` produces binary; `make test` runs tests.

Milestone 11 — Polish and hardening
- 11.1 Resource limit handling
  - Detect EMFILE/ENFILE and provide user guidance or throttle workers
  - Acceptance: Graceful error message when FD limits hit.
- 11.2 CLI ergonomics and error text improvements
  - Acceptance: UX review and small revisions applied.
- 11.3 Optional: integrate gopacket behind build tag for improved stealth
  - Acceptance: Separate build target documented.

---

Task sequencing notes
- Tasks are ordered so early milestones provide a working binary that can scan TCP ports locally; later milestones add UDP, stealth, detection and robustness.
- Keep each task small and testable; prefer interface injection and fakes for unit tests to avoid network dependence.
- When implementing stealth/SYN, prefer gating behavior and clear error messages rather than cross-platform raw socket hacks.

---

How to use this task list
- Pick tasks sequentially per milestone.
- Create a small branch per milestone (e.g., feat/cli, feat/tcp-scanner).
- Ensure each PR includes unit tests for new behavior and documentation updates where applicable.

End of tasks.