package scanner

import (
	"context"
	"fmt"
	"net"
	"os"
	"strings"
	"syscall"
	"time"

	"portprowler/port"
)

// UDPScan performs a UDP probe to the specified IP and port using the provided timeout.
// Behavior:
//   - any application-level response -> "open"
//   - ICMP port-unreachable surfaced as connection-refused -> "closed"
//   - timeout / no response -> "filtered"
func UDPScan(ctx context.Context, ip string, portNum uint16, timeout time.Duration, verbose bool) port.PortResult {
	addr := fmt.Sprintf("%s:%d", ip, portNum)
	res := port.PortResult{
		IP:        ip,
		Port:      portNum,
		Proto:     "udp",
		State:     "filtered",
		RTTMillis: 0,
	}

	raddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		res.Error = err.Error()
		if verbose {
			fmt.Printf("[verbose] udp resolve error %s: %v\n", addr, err)
		}
		return res
	}

	conn, err := net.DialUDP("udp", nil, raddr)
	if err != nil {
		// classify dial error
		if strings.Contains(err.Error(), "connection refused") || isConnRefusedErr(err) {
			res.State = "closed"
			res.Error = err.Error()
			if verbose {
				fmt.Printf("[verbose] udp dial conn refused %s: %v\n", addr, err)
			}
			return res
		}
		res.Error = err.Error()
		if verbose {
			fmt.Printf("[verbose] udp dial error %s: %v\n", addr, err)
		}
		return res
	}
	defer conn.Close()

	// send a small probe (single zero byte) and wait for a response
	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		res.Error = err.Error()
		if verbose {
			fmt.Printf("[verbose] udp setdeadline error %s: %v\n", addr, err)
		}
		return res
	}

	start := time.Now()
	_, err = conn.Write([]byte{0x00})
	if err != nil {
		// write error may indicate ICMP unreachable on some platforms
		if strings.Contains(err.Error(), "connection refused") || isConnRefusedErr(err) {
			res.State = "closed"
			res.Error = err.Error()
			if verbose {
				fmt.Printf("[verbose] udp write conn refused %s: %v\n", addr, err)
			}
			return res
		}
		res.Error = err.Error()
		if verbose {
			fmt.Printf("[verbose] udp write error %s: %v\n", addr, err)
		}
		// treat as filtered/fuzzy
		return res
	}

	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	rtt := time.Since(start)
	res.RTTMillis = rtt.Milliseconds()

	if err == nil && n > 0 {
		res.State = "open"
		if verbose {
			fmt.Printf("[verbose] udp got %d bytes from %s rtt=%dms\n", n, addr, res.RTTMillis)
		}
		return res
	}

	// classify read error
	if ne, ok := err.(net.Error); ok && ne.Timeout() {
		res.State = "filtered"
		res.Error = "timeout"
		if verbose {
			fmt.Printf("[verbose] udp timeout %s\n", addr)
		}
		return res
	}

	if err != nil {
		// attempt to detect connection refused from wrapped errors
		if strings.Contains(err.Error(), "connection refused") || isConnRefusedErr(err) {
			res.State = "closed"
			res.Error = err.Error()
			if verbose {
				fmt.Printf("[verbose] udp conn refused %s: %v\n", addr, err)
			}
			return res
		}
		// fallback: treat as filtered with error text
		res.State = "filtered"
		res.Error = err.Error()
		if verbose {
			fmt.Printf("[verbose] udp read error %s: %v\n", addr, err)
		}
		return res
	}

	// no data and no error -> filtered
	res.State = "filtered"
	return res
}

// isConnRefusedErr attempts to detect connection-refused semantics from various error wrappers.
func isConnRefusedErr(err error) bool {
	// unwrap common net.OpError -> SyscallError -> Errno patterns
	if err == nil {
		return false
	}
	// check for *os.SyscallError and syscall.ECONNREFUSED
	if se, ok := err.(*os.SyscallError); ok {
		if se.Err == syscall.ECONNREFUSED {
			return true
		}
	}
	// check for net.OpError wrapping SyscallError
	if oe, ok := err.(*net.OpError); ok {
		if se, ok := oe.Err.(*os.SyscallError); ok {
			if se.Err == syscall.ECONNREFUSED {
				return true
			}
		}
		if errno, ok := oe.Err.(syscall.Errno); ok {
			if errno == syscall.ECONNREFUSED {
				return true
			}
		}
	}
	// fallback string check
	if strings.Contains(err.Error(), "connection refused") {
		return true
	}
	return false
}
