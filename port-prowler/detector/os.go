package detector

import (
	"strings"

	"portprowler/port"
)

// DetectOS analyzes a slice of open PortResult entries and returns a best-effort
// OS guess and a confidence string ("low"|"medium"|"high").
// This implementation uses banner substrings and simple open-port patterns.
// It is conservative and designed for unit testing (deterministic string checks).
func DetectOS(results []port.PortResult) (string, string) {
	if len(results) == 0 {
		return "", ""
	}

	// aggregate scores
	scores := map[string]int{
		"windows":  0,
		"linux":    0,
		"embedded": 0,
	}
	/*
		// helper to award points based on substring presence
		addIfContains := func(s string, substrs []string, pts int) {
			ls := strings.ToLower(s)
			for _, sub := range substrs {
				if strings.Contains(ls, sub) {
					for _, k := range []string{"windows", "linux", "embedded"} {
						_ = k // no-op to appease linters where needed
					}
					for _, subKey := range substrs {
						_ = subKey
					}
					// award to appropriate buckets handled below per call site
					_ = pts
				}
			}
		}
	*/

	// Iterate results and apply heuristics
	for _, r := range results {
		b := strings.ToLower(strings.TrimSpace(r.ServiceBanner + " " + r.Service))

		// Windows hints
		if strings.Contains(b, "windows") || strings.Contains(b, "microsoft") || strings.Contains(b, "mssql") {
			scores["windows"] += 3
		}
		if strings.Contains(b, "rdp") || r.Port == 3389 {
			scores["windows"] += 4
		}
		if strings.Contains(b, "iis") || strings.Contains(b, "winhttp") {
			scores["windows"] += 2
		}

		// Linux/Unix hints
		if strings.Contains(b, "linux") || strings.Contains(b, "ubuntu") || strings.Contains(b, "debian") ||
			strings.Contains(b, "centos") || strings.Contains(b, "red hat") {
			scores["linux"] += 3
		}
		// service-based hints
		if strings.Contains(b, "ssh") || strings.Contains(b, "sshd") {
			scores["linux"] += 2
		}
		if strings.Contains(b, "nginx") || strings.Contains(b, "apache") || strings.Contains(b, "http/") {
			scores["linux"] += 2
		}
		if strings.Contains(b, "mysql") || strings.Contains(b, "mariadb") || strings.Contains(b, "postgres") || strings.Contains(b, "postgresql") {
			scores["linux"] += 2
		}

		// Embedded / network device hints
		if strings.Contains(b, "cisco") || strings.Contains(b, "ios") || strings.Contains(b, "ubnt") ||
			strings.Contains(b, "router") || strings.Contains(b, "firmware") {
			scores["embedded"] += 3
		}

		// Port-pattern heuristics (additive)
		switch r.Port {
		case 3389:
			scores["windows"] += 4
		case 135, 139, 445:
			scores["windows"] += 3
		case 22, 80, 443, 3306, 5432:
			// these are common on Linux hosts (SSH, HTTP, MySQL, Postgres)
			scores["linux"] += 1
		case 1900, 5000:
			scores["embedded"] += 1
		}
	}

	// Tally best candidate
	best := ""
	bestScore := 0
	for osn, sc := range scores {
		if sc > bestScore {
			best = osn
			bestScore = sc
		}
	}

	if bestScore == 0 {
		return "", ""
	}

	// Map score to confidence
	conf := "low"
	if bestScore >= 6 {
		conf = "high"
	} else if bestScore >= 3 {
		conf = "medium"
	}

	// Normalize OS name
	switch best {
	case "windows":
		return "Windows", conf
	case "linux":
		return "Linux", conf
	case "embedded":
		return "embedded", conf
	default:
		return "", ""
	}
}

// DetectOSForResult is a convenience helper that runs DetectOS with a single result.
// It enables per-result OS heuristics when global context isn't available.
func DetectOSForResult(r port.PortResult) (string, string) {
	return DetectOS([]port.PortResult{r})
}
