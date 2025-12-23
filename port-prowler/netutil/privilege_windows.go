//go:build windows
// +build windows

package netutil

import "fmt"

// On Windows builds we conservatively report no raw-socket support in this build.
func CanOpenRawSocket() (bool, error) {
    return false, fmt.Errorf("raw sockets not supported on Windows in this build")
}