package netutil

import (
	"errors"
	"net"
)

// ResolveTargetToIPv4 resolves the given target (hostname or IP string)
// and returns the first IPv4 address as a string.
// If the target is an IPv6-only host, an error is returned.
func ResolveTargetToIPv4(target string) (string, error) {
	// If target is already an IP literal, accept IPv4 only.
	if ip := net.ParseIP(target); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			return ip4.String(), nil
		}
		return "", errors.New("IPv6 addresses are not supported")
	}

	ips, err := net.LookupIP(target)
	if err != nil {
		return "", err
	}
	var firstV6 net.IP
	for _, ip := range ips {
		if v4 := ip.To4(); v4 != nil {
			return v4.String(), nil
		}
		if firstV6 == nil {
			firstV6 = ip
		}
	}
	if firstV6 != nil {
		return "", errors.New("hostname resolves only to IPv6 addresses; IPv6 is not supported")
	}
	return "", errors.New("no A records found for host")
}
