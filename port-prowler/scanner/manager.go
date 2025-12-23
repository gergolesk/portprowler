package scanner

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"portprowler/detector"
	"portprowler/port"
)

// Config contains runtime configuration for the Manager.
type Config struct {
	Target        string
	IP            string
	Ports         []uint16
	ScanTCP       bool
	ScanUDP       bool
	ScanStealth   bool
	Workers       int
	Timeout       time.Duration
	ServiceDetect bool
	OSDetect      bool
	Verbose       bool
}

// Manager orchestrates job creation and worker pool.
type Manager struct {
	cfg Config
}

// NewManager creates a new Manager with the provided config.
func NewManager(cfg Config) *Manager {
	return &Manager{cfg: cfg}
}

// sentinel error returned when stealth requested but privileges missing
var ErrNeedPriv = errors.New("stealth requires raw socket privileges")

// Run starts the worker pool and returns a results channel. It returns an error for invalid config.
// The returned channel will be closed once all work is completed.
func (m *Manager) Run(ctx context.Context) (<-chan port.PortResult, error) {
	if m.cfg.Target == "" || m.cfg.IP == "" {
		return nil, errors.New("invalid manager config: missing target/ip")
	}
	if len(m.cfg.Ports) == 0 {
		return nil, errors.New("no ports to scan")
	}

	// Determine scan types for jobs
	scanTypes := make([]port.ScanType, 0, 3)
	if m.cfg.ScanStealth {
		scanTypes = append(scanTypes, port.ScanStealth)
	}
	if m.cfg.ScanTCP {
		scanTypes = append(scanTypes, port.ScanTCP)
	}
	if m.cfg.ScanUDP {
		scanTypes = append(scanTypes, port.ScanUDP)
	}
	// Default to TCP if none specified
	if len(scanTypes) == 0 {
		scanTypes = append(scanTypes, port.ScanTCP)
	}

	jobCount := len(m.cfg.Ports)
	jobChan := make(chan port.PortJob, jobCount)
	resultsChan := make(chan port.PortResult, jobCount*len(scanTypes))

	workers := m.cfg.Workers
	if workers <= 0 {
		workers = 1
	}

	var wg sync.WaitGroup

	// start workers
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case job, ok := <-jobChan:
					if !ok {
						return
					}
					// Execute scan types sequentially for this job.
					for _, st := range job.ScanTypes {
						select {
						case <-ctx.Done():
							return
						default:
						}
						if st == port.ScanTCP {
							// perform real TCP connect scan
							if m.cfg.Verbose {
								fmt.Printf("[verbose] worker: scanning tcp %s:%d\n", job.IP, job.Port)
							}
							res := TCPScan(ctx, job.IP, job.Port, m.cfg.Timeout, m.cfg.Verbose)
							// attach original target string from job
							res.Target = job.Target

							// If open and service detection enabled, run detector and use updated result.
							if res.State == "open" && m.cfg.ServiceDetect {
								dcfg := detector.Config{
									ServiceDetect: m.cfg.ServiceDetect,
									Timeout:       m.cfg.Timeout,
									Verbose:       m.cfg.Verbose,
								}
								res = detector.DetectService(ctx, dcfg, res)
							}

							// If open and OS detection enabled, run OS heuristics (prefer after service detection).
							if res.State == "open" && m.cfg.OSDetect {
								if osGuess, osConf := detector.DetectOSForResult(res); osGuess != "" {
									res.OSGuess = osGuess
									// Overwrite Confidence with OS confidence per spec (best-effort).
									res.Confidence = osConf
								}
							}

							select {
							case <-ctx.Done():
								return
							case resultsChan <- res:
							}
							continue
						}
						if st == port.ScanUDP {
							// perform real UDP probe
							if m.cfg.Verbose {
								fmt.Printf("[verbose] worker: scanning udp %s:%d\n", job.IP, job.Port)
							}
							res := UDPScan(ctx, job.IP, job.Port, m.cfg.Timeout, m.cfg.Verbose)
							res.Target = job.Target

							// For UDP open results, optionally run service detection too (best-effort).
							if res.State == "open" && m.cfg.ServiceDetect {
								dcfg := detector.Config{
									ServiceDetect: m.cfg.ServiceDetect,
									Timeout:       m.cfg.Timeout,
									Verbose:       m.cfg.Verbose,
								}
								res = detector.DetectService(ctx, dcfg, res)
							}

							// For UDP open results, optionally run OS detection if requested.
							if res.State == "open" && m.cfg.OSDetect {
								if osGuess, osConf := detector.DetectOSForResult(res); osGuess != "" {
									res.OSGuess = osGuess
									res.Confidence = osConf
								}
							}

							select {
							case <-ctx.Done():
								return
							case resultsChan <- res:
							}
							continue
						}
						if st == port.ScanStealth {
							// perform stealth (SYN) scan via scaffold
							if m.cfg.Verbose {
								fmt.Printf("[verbose] worker: scanning stealth %s:%d\n", job.IP, job.Port)
							}
							res := StealthScan(ctx, job.IP, job.Port, m.cfg.Timeout, m.cfg.Verbose)
							res.Target = job.Target

							// If open and service detection enabled, run detector and use updated result.
							if res.State == "open" && m.cfg.ServiceDetect {
								dcfg := detector.Config{
									ServiceDetect: m.cfg.ServiceDetect,
									Timeout:       m.cfg.Timeout,
									Verbose:       m.cfg.Verbose,
								}
								res = detector.DetectService(ctx, dcfg, res)
							}

							// If open and OS detection enabled, run OS heuristics.
							if res.State == "open" && m.cfg.OSDetect {
								if osGuess, osConf := detector.DetectOSForResult(res); osGuess != "" {
									res.OSGuess = osGuess
									res.Confidence = osConf
								}
							}

							select {
							case <-ctx.Done():
								return
							case resultsChan <- res:
							}
							continue
						}
						// For other scan types keep previous placeholder behavior for now.
						res := port.PortResult{
							Target: job.Target,
							IP:     job.IP,
							Port:   job.Port,
							Proto:  string(st),
							State:  "unknown",
						}
						select {
						case <-ctx.Done():
							return
						case resultsChan <- res:
						}
					}
				}
			}
		}()
	}

	// dispatcher goroutine: enqueue jobs then close jobChan and wait for workers to finish, then close resultsChan
	go func() {
		// enqueue jobs
		for _, p := range m.cfg.Ports {
			select {
			case <-ctx.Done():
				break
			default:
			}
			job := port.PortJob{
				Target:    m.cfg.Target,
				IP:        m.cfg.IP,
				Port:      p,
				ScanTypes: scanTypes,
			}
			jobChan <- job
		}
		close(jobChan)
		// wait for workers
		wg.Wait()
		// close results
		close(resultsChan)
	}()

	return resultsChan, nil
}
