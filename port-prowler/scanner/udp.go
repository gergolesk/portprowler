package scanner

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"strings"
	"syscall"
	"time"

	"portprowler/port"
)

// UDPScan performs a UDP probe to the specified IP and port using the provided timeout.
// Behavior (updated):
//   - any application-level response (or valid DNS response for 53/udp) -> "open"
//   - ICMP port-unreachable surfaced as connection-refused -> "closed"
//   - timeout / no response -> "open|filtered"
func UDPScan(ctx context.Context, ip string, portNum uint16, timeout time.Duration, verbose bool) port.PortResult {
	addr := fmt.Sprintf("%s:%d", ip, portNum)
	res := port.PortResult{
		IP:        ip,
		Port:      portNum,
		Proto:     "udp",
		State:     "open|filtered",
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

	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		res.Error = err.Error()
		if verbose {
			fmt.Printf("[verbose] udp setdeadline error %s: %v\n", addr, err)
		}
		return res
	}

	// Choose probe payload.
	var payload []byte
	var dnsTXID uint16
	if portNum == 53 {
		var perr error
		payload, dnsTXID, perr = buildDNSQueryA("example.com")
		if perr != nil {
			// fallback to a single byte if DNS query build fails (shouldn't happen)
			payload = []byte{0x00}
		}
	} else {
		// generic probe: single zero byte
		payload = []byte{0x00}
	}

	start := time.Now()
	_, err = conn.Write(payload)
	if err != nil {
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
		return res
	}

	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	rtt := time.Since(start)
	res.RTTMillis = rtt.Milliseconds()

	if err == nil && n > 0 {
		// If this is DNS, validate response shape and TXID to reduce false positives.
		if portNum == 53 {
			if isValidDNSResponse(buf[:n], dnsTXID) {
				res.State = "open"
				if verbose {
					fmt.Printf("[verbose] udp dns response %d bytes from %s rtt=%dms\n", n, addr, res.RTTMillis)
				}
				return res
			}
			// If we got bytes but DNS validation failed, still treat as open (some middleboxes answer oddly),
			// but annotate in Error for debugging.
			res.State = "open"
			res.Error = "dns response not validated"
			if verbose {
				fmt.Printf("[verbose] udp got %d bytes from %s but dns validation failed rtt=%dms\n", n, addr, res.RTTMillis)
			}
			return res
		}

		// Generic UDP: any bytes -> open
		res.State = "open"
		if verbose {
			fmt.Printf("[verbose] udp got %d bytes from %s rtt=%dms\n", n, addr, res.RTTMillis)
		}
		return res
	}

	// classify read error
	if ne, ok := err.(net.Error); ok && ne.Timeout() {
		res.State = "open|filtered"
		res.Error = "timeout"
		if verbose {
			fmt.Printf("[verbose] udp timeout %s\n", addr)
		}
		return res
	}

	if err != nil {
		if strings.Contains(err.Error(), "connection refused") || isConnRefusedErr(err) {
			res.State = "closed"
			res.Error = err.Error()
			if verbose {
				fmt.Printf("[verbose] udp conn refused %s: %v\n", addr, err)
			}
			return res
		}
		res.State = "open|filtered"
		res.Error = err.Error()
		if verbose {
			fmt.Printf("[verbose] udp read error %s: %v\n", addr, err)
		}
		return res
	}

	// no data and no error -> open|filtered
	res.State = "open|filtered"
	return res
}

// buildDNSQueryA builds a minimal DNS query asking for A record of name.
// Returns payload and transaction ID.
func buildDNSQueryA(name string) ([]byte, uint16, error) {
	// TXID
	var txidBytes [2]byte
	if _, err := rand.Read(txidBytes[:]); err != nil {
		return nil, 0, err
	}
	txid := binary.BigEndian.Uint16(txidBytes[:])

	// DNS header (12 bytes)
	// ID, Flags, QDCOUNT, ANCOUNT, NSCOUNT, ARCOUNT
	hdr := make([]byte, 12)
	binary.BigEndian.PutUint16(hdr[0:2], txid)
	// flags: standard query, recursion desired
	binary.BigEndian.PutUint16(hdr[2:4], 0x0100)
	binary.BigEndian.PutUint16(hdr[4:6], 1) // QDCOUNT=1

	// QNAME: labels
	qname, err := encodeDNSName(name)
	if err != nil {
		return nil, 0, err
	}

	// QTYPE=A (1), QCLASS=IN (1)
	qtail := make([]byte, 4)
	binary.BigEndian.PutUint16(qtail[0:2], 1)
	binary.BigEndian.PutUint16(qtail[2:4], 1)

	payload := append(hdr, qname...)
	payload = append(payload, qtail...)
	return payload, txid, nil
}

func encodeDNSName(name string) ([]byte, error) {
	name = strings.TrimSpace(name)
	name = strings.TrimSuffix(name, ".")
	if name == "" {
		return nil, fmt.Errorf("empty dns name")
	}
	parts := strings.Split(name, ".")
	out := make([]byte, 0, len(name)+2)
	for _, p := range parts {
		if p == "" {
			return nil, fmt.Errorf("invalid dns name: %q", name)
		}
		if len(p) > 63 {
			return nil, fmt.Errorf("dns label too long: %q", p)
		}
		out = append(out, byte(len(p)))
		out = append(out, []byte(p)...)
	}
	out = append(out, 0x00) // terminator
	return out, nil
}

// isValidDNSResponse does a minimal sanity check:
// - at least 12 bytes (DNS header)
// - TXID matches
// - QR bit set (response)
func isValidDNSResponse(pkt []byte, wantTXID uint16) bool {
	if len(pkt) < 12 {
		return false
	}
	gotTXID := binary.BigEndian.Uint16(pkt[0:2])
	if gotTXID != wantTXID {
		return false
	}
	flags := binary.BigEndian.Uint16(pkt[2:4])
	qr := (flags & 0x8000) != 0
	return qr
}

// isConnRefusedErr attempts to detect connection-refused semantics from various error wrappers.
func isConnRefusedErr(err error) bool {
	if err == nil {
		return false
	}
	if se, ok := err.(*os.SyscallError); ok {
		if se.Err == syscall.ECONNREFUSED {
			return true
		}
	}
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
	if strings.Contains(err.Error(), "connection refused") {
		return true
	}
	return false
}
