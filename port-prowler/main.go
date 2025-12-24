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
		fmt.Fprintln(os.Stderr, "error: -p <ports> is required")
		flag.Usage()
		os.Exit(2)
	}

	ports, err := port.ParsePortSpec(*portsSpec)
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid ports spec: %v\n", err)
		os.Exit(2)
	}

	ipStr, err := netutil.ResolveTargetToIPv4(target)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to resolve target: %v\n", err)
		os.Exit(4)
	}

	// Minimal success output for milestone 1
	fmt.Printf("Target: %s -> %s\n", target, ipStr)
	fmt.Printf("Ports: %v\n", ports)
	fmt.Printf("Scan modes: tcp=%v udp=%v stealth=%v\n", *tcp, *udp, *stealth)
	fmt.Printf("Service detection: %v, OS detection: %v\n", *serviceDetect, *osDetect)
	fmt.Printf("Workers: %d, timeout: %v, verbose: %v\n", *workers, *to, *verbose)
	if *fileOut != "" {
		fmt.Printf("File output: %s\n", *fileOut)
	}

	// Build manager config and run manager (Milestone 2)
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
		// Map privilege/config error for stealth -> exit code 3 per spec
		if errors.Is(err, scanner.ErrNeedPriv) {
			fmt.Fprintln(os.Stderr, "Stealth scan (-s) requires raw socket privileges. Rerun with elevated privileges (root/CAP_NET_RAW) or remove -s to use TCP connect. No fallback is performed.")
			os.Exit(3)
		}
		fmt.Fprintf(os.Stderr, "failed to start scanner manager: %v\n", err)
		os.Exit(4)
	}

	// Render output into buffer first
	var buf bytes.Buffer
	output.PrintTable(resultsCh, &buf)

	// Copy buffer to stdout
	if _, err := os.Stdout.Write(buf.Bytes()); err != nil {
		fmt.Fprintf(os.Stderr, "failed to write to stdout: %v\n", err)
		os.Exit(4)
	}

	// ensure result directory exists
	outDir := "result"
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "failed to create result dir: %v\n", err)
		os.Exit(4)
	}

	if *fileOut != "" {
		outPath := filepath.Join(outDir, *fileOut)

		if err := output.WriteAtomic(outPath, buf.Bytes()); err != nil {
			fmt.Fprintf(os.Stderr, "failed to write output file: %v\n", err)
			os.Exit(4)
		}
	}
}
