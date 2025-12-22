package detector

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"portprowler/port"
	"portprowler/sigs"
)

// Config contains the minimal fields detector needs (no import cycle with scanner).
type Config struct {
	ServiceDetect bool
	Timeout       time.Duration
	Verbose       bool
}

// DetectService enriches a PortResult with service detection info when applicable.
//   - Only runs when result.State == "open" AND cfg.ServiceDetect == true.
//   - Uses result.ServiceBanner if present; otherwise attempts lightweight probes
//     for common TCP ports (80/8080/8000 => HTTP HEAD, 25 => SMTP HELO).
func DetectService(ctx context.Context, cfg Config, res port.PortResult) port.PortResult {
	if !cfg.ServiceDetect || res.State != "open" {
		return res
	}

	// If banner already present (e.g., TCPScan populated it), use it.
	banner := strings.TrimSpace(res.ServiceBanner)

	// If empty, attempt minimal probes for common TCP ports.
	if banner == "" && res.Proto == "tcp" {
		addr := net.JoinHostPort(res.IP, fmt.Sprintf("%d", res.Port))
		// use Dial with timeout
		dialTimeout := cfg.Timeout
		if dialTimeout <= 0 {
			dialTimeout = 1 * time.Second
		}
		conn, err := net.DialTimeout("tcp", addr, dialTimeout)
		if err == nil {
			// Ensure we close the connection.
			defer conn.Close()
			conn.SetDeadline(time.Now().Add(dialTimeout))

			var probe string
			switch res.Port {
			case 80, 8080, 8000:
				probe = "HEAD / HTTP/1.0\r\n\r\n"
			case 25:
				probe = "HELO test\r\n"
			default:
				// Generic read attempt: no probe write, just try to read any banner the server may send.
			}

			if probe != "" {
				_, _ = conn.Write([]byte(probe))
			}
			// Read up to 2048 bytes
			buf := make([]byte, 2048)
			n, _ := conn.Read(buf)
			if n > 0 {
				banner = strings.TrimSpace(string(buf[:n]))
			}
		} else {
			// Dial failed; leave banner empty and record error in res.Error for visibility.
			if cfg.Verbose {
				res.Error = fmt.Sprintf("service-detect: dial error: %v", err)
			}
		}
	}

	// If we have a banner, match against signatures.
	if banner != "" {
		if svc, conf, ok := sigs.Detect(banner); ok {
			res.Service = svc
			res.Confidence = conf
		}
		res.ServiceBanner = banner
	}

	return res
}
