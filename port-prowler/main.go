package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"portprowler/detector"
	"portprowler/netutil"
	"portprowler/output"
	"portprowler/port"
	"portprowler/scanner"
)

func main() {
	portsSpec := flag.String("p", "", "ports (e.g. 22,80,8000-8100) (required)")
	tcp := flag.Bool("tcp", false, "perform tcp connect scan")
	udp := flag.Bool("udp", false, "perform udp scan")
	stealth := flag.Bool("s", false, "perform stealth scan (requires privileges)")
	fileOut := flag.String("f", "", "write output to file (overwrite, atomic)")
	serviceDetect := flag.Bool("service-detect", false, "enable service detection (opt-in)")
	osDetect := flag.Bool("os-detect", false, "enable os detection (opt-in)")
	workers := flag.Int("c", 100, "worker count (default 100)")
	to := flag.Duration("t", time.Second, "per-probe timeout (default 1s)")
	verbose := flag.Bool("v", false, "verbose logging")
	flag.Parse()

	if flag.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "error: target positional argument required")
		flag.Usage()
		os.Exit(2)
	}
	target := flag.Arg(0)

	if *portsSpec == "" {
		fmt.Fprintln(os.Stderr, "error: -p <ports> is required (examples: -p 22 -p 22,80 -p 1-1024 -p 22,80,8000-8100)")
		flag.Usage()
		os.Exit(2)
	}

	// Validate worker count early
	if *workers <= 0 || *workers > 10000 {
		fmt.Fprintln(os.Stderr, "error: invalid worker count (-c). Provide a positive value up to 10000.")
		os.Exit(2)
	}

	ports, err := port.ParsePortSpec(*portsSpec)
	if err != nil {
		// make invalid port spec error clearer with example
		fmt.Fprintf(os.Stderr, "Invalid port spec %q: %v\nExamples: -p 22  -p 22,80  -p 1-1024  -p 22,80,8000-8100\n", *portsSpec, err)
		os.Exit(2)
	}

	ipStr, err := netutil.ResolveTargetToIPv4(target)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to resolve target: %v\n", err)
		os.Exit(4)
	}

	// Print Target line now; OS is computed after scan completes and printed next.
	fmt.Printf("Target: %s -> %s\n", target, ipStr)

	cfg := scanner.Config{
		Target:        target,
		IP:            ipStr,
		Ports:         ports,
		ScanTCP:       *tcp,
		ScanUDP:       *udp,
		ScanStealth:   *stealth,
		Workers:       *workers,
		Timeout:       *to,
		ServiceDetect: *serviceDetect,
		OSDetect:      *osDetect,
		Verbose:       *verbose,
	}

	mgr := scanner.NewManager(cfg)

	ctx := context.Background()
	resultsCh, err := mgr.Run(ctx)
	if err != nil {
		if errors.Is(err, scanner.ErrNeedPriv) {
			fmt.Fprintln(os.Stderr, "Stealth scan (-s) requires raw socket privileges. Rerun with elevated privileges (root/CAP_NET_RAW) or remove -s to use TCP connect. No fallback is performed.")
			os.Exit(3)
		}
		fmt.Fprintf(os.Stderr, "failed to start scanner manager: %v\n", err)
		os.Exit(4)
	}

	// Collect all results into memory so we can run OS detection per-target (single OS guess).
	var results []port.PortResult
	for r := range resultsCh {
		results = append(results, r)
	}

	// Perform OS detection once for the target (based on all open-port results), if requested.
	var osLine string
	if cfg.OSDetect {
		if osGuess, osConf := detector.DetectOS(results); osGuess != "" {
			osLine = fmt.Sprintf("OS: %s (confidence: %s)\n", osGuess, osConf)
		} else {
			osLine = "OS: unknown\n"
		}
	} else {
		osLine = "OS: disabled\n"
	}

	// Print OS line, then Ports and Scan modes (match requested output ordering).
	fmt.Print(osLine)
	fmt.Printf("Ports: %s\n", *portsSpec)
	fmt.Printf("Scan modes: tcp=%v udp=%v stealth=%v\n", cfg.ScanTCP, cfg.ScanUDP, cfg.ScanStealth)
	fmt.Printf("Service detection: %v, OS detection: %v\n", cfg.ServiceDetect, cfg.OSDetect)
	fmt.Printf("Workers: %d, timeout: %v, verbose: %v\n", cfg.Workers, cfg.Timeout, cfg.Verbose)
	if *fileOut != "" {
		fmt.Printf("File output: %s\n", *fileOut)
	}

	// Render table into buffer
	var buf bytes.Buffer
	output.PrintTableFromSlice(results, &buf)

	// Copy buffer to stdout
	if _, err := os.Stdout.Write(buf.Bytes()); err != nil {
		fmt.Fprintf(os.Stderr, "failed to write to stdout: %v\n", err)
		os.Exit(4)
	}

	// If file output requested, ensure parent dir exists and write atomically
	if *fileOut != "" {
		outDir := filepath.Dir(*fileOut)
		if outDir == "" || outDir == "." {
			outDir = ""
		}
		if outDir != "" {
			if err := os.MkdirAll(outDir, 0o755); err != nil {
				fmt.Fprintf(os.Stderr, "failed to create output directory %s: %v\n", outDir, err)
				os.Exit(4)
			}
		}
		if err := output.WriteAtomic(*fileOut, buf.Bytes()); err != nil {
			fmt.Fprintf(os.Stderr, "failed to write output file: %v\n", err)
			os.Exit(4)
		}
	}
}
