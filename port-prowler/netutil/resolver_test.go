package netutil

import (
	"net"
	"testing"
)

// LookupIPFunc is a variable to allow injection/mocking in tests.
// By default it points to net.LookupIP.
var LookupIPFunc = net.LookupIP

// ResolveTargetToIPv4 resolves the given target (hostname or IP string)
// and returns the first IPv4 address as a string.
// If the target is an IPv6-only host, an error is returned.

func TestResolveTargetToIPv4_LiteralIPv4(t *testing.T) {
	ip, err := ResolveTargetToIPv4("1.2.3.4")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ip != "1.2.3.4" {
		t.Fatalf("got %s want 1.2.3.4", ip)
	}
}
