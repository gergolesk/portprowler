//go:build !windows
// +build !windows

package netutil

import "os"

// CanOpenRawSocket returns true when the process has privileges to open raw sockets.
// Unix implementation: require euid == 0.
func CanOpenRawSocket() (bool, error) {
	return os.Geteuid() == 0, nil
}
