package sigs

import "strings"

// Small signature DB mapping substrings to service name and confidence.
// Matching is done case-insensitively.
var signatures = []struct {
	Substr     string
	Service    string
	Confidence string
}{
	{"ssh-", "ssh", "high"},     // OpenSSH banners include "SSH-"
	{"http/", "http", "medium"}, // e.g. "HTTP/1.1"
	{"nginx", "http/nginx", "high"},
	{"220 ", "smtp", "medium"}, // SMTP greeting starts with "220 "
	{"dns", "dns", "medium"},   // generic DNS hint
}

// Detect examines banner text and returns service, confidence and found flag.
func Detect(banner string) (service, confidence string, found bool) {
	b := banner
	if b == "" {
		return "", "", false
	}
	// Normalize to lower-case once for case-insensitive substring checks.
	lb := strings.ToLower(b)
	for _, s := range signatures {
		if strings.Contains(lb, strings.ToLower(s.Substr)) {
			return s.Service, s.Confidence, true
		}
	}
	return "", "", false
}
