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

// TCPScan performs a TCP connect scan to the specified IP and port using the provided timeout.
// It returns a PortResult populated with proto="tcp", State {open|closed|filtered}, and RTTMillis.
func TCPScan(ctx context.Context, ip string, portNum uint16, timeout time.Duration, verbose bool) port.PortResult {
	addr := fmt.Sprintf("%s:%d", ip, portNum)
	start := time.Now()
	conn, err := net.DialTimeout("tcp", addr, timeout)
	rtt := time.Since(start)

	res := port.PortResult{
		IP:        ip,
		Port:      portNum,
		Proto:     "tcp",
		State:     "filtered",
		RTTMillis: rtt.Milliseconds(),
	}

	if err == nil {
		// success -> open
		res.State = "open"
		// close connection immediately; banner grabbing is optional and done elsewhere
		_ = conn.Close()
		if verbose {
			fmt.Printf("[verbose] tcp connect success %s rtt=%dms\n", addr, res.RTTMillis)
		}
		return res
	}

	// classify error
	if ne, ok := err.(net.Error); ok && ne.Timeout() {
		res.State = "filtered"
		res.Error = "timeout"
		if verbose {
			fmt.Printf("[verbose] tcp timeout %s\n", addr)
		}
		return res
	}

	// connection refused detection
	if opErr, ok := err.(*net.OpError); ok {
		// unwrap syscall error if present
		if se, ok := opErr.Err.(*os.SyscallError); ok {
			if se.Err == syscall.ECONNREFUSED {
				res.State = "closed"
				res.Error = "connection refused"
				if verbose {
					fmt.Printf("[verbose] tcp conn refused %s\n", addr)
				}
				return res
			}
		}
		// sometimes opErr.Err may directly be syscall.Errno
		if errno, ok := opErr.Err.(syscall.Errno); ok {
			if errno == syscall.ECONNREFUSED {
				res.State = "closed"
				res.Error = "connection refused"
				if verbose {
					fmt.Printf("[verbose] tcp conn refused %s\n", addr)
				}
				return res
			}
		}
	}

	// fallback check for common substrings
	errStr := err.Error()
	if errStr != "" {
		if contains := (strings.Contains(errStr, "refused") || strings.Contains(errStr, "connection refused")); contains {
			res.State = "closed"
			res.Error = errStr
			if verbose {
				fmt.Printf("[verbose] tcp error (assume closed) %s: %s\n", addr, errStr)
			}
			return res
		}
	}

	// default to filtered with error text
	res.State = "filtered"
	res.Error = err.Error()
	if verbose {
		fmt.Printf("[verbose] tcp error %s: %v\n", addr, err)
	}
	return res
}
