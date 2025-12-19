package port

// ScanType represents the type of scan to perform for a job.
type ScanType string

const (
	ScanTCP     ScanType = "tcp"
	ScanUDP     ScanType = "udp"
	ScanStealth ScanType = "stealth"
)

// PortJob represents a scanning job for a single port and one or more scan types.
type PortJob struct {
	Target    string
	IP        string
	Port      uint16
	ScanTypes []ScanType // ordered list of scans to run sequentially for the port
}

// PortResult represents the result of scanning a single port/protocol.
type PortResult struct {
	Target        string
	IP            string
	Port          uint16
	Proto         string // "tcp" | "udp" | "stealth"
	State         string // "open" | "closed" | "filtered" | "unknown"
	Service       string
	ServiceBanner string
	OSGuess       string
	Confidence    string // "low"|"medium"|"high"
	Error         string
	RTTMillis     int64
}
