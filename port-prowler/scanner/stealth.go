package scanner

import (
	"context"
	"fmt"
	"time"

	"portprowler/netutil"
	"portprowler/port"
)

// StealthScan is a minimal scaffold for a SYN/stealth scan.
// Behavior:
//   - Returns PortResult.Proto == "stealth".
//   - Fails early if raw-socket privileges are not available.
//   - When privileges present this is a stub (not performing real raw-socket SYNs).
//
// Notes:
//   - This file intentionally implements a conservative, testable stub. A full
//     Linux-focused raw-socket implementation may be added behind build tags later.
func StealthScan(ctx context.Context, ip string, portNum uint16, timeout time.Duration, verbose bool) port.PortResult {
	res := port.PortResult{
		IP:        ip,
		Port:      portNum,
		Proto:     "stealth",
		State:     "filtered",
		RTTMillis: 0,
	}

	ok, err := netutil.CanOpenRawSocket()
	if err != nil {
		res.Error = fmt.Sprintf("stealth privilege check error: %v", err)
		return res
	}
	if !ok {
		res.Error = "stealth scan requires raw socket privileges"
		return res
	}

	// Privileges present but full stealth implementation not provided in this milestone.
	res.Error = "stealth scan not implemented in this build (stub)"
	return res
}
