package output

import (
	"fmt"
	"io"
	"sort"
	"text/tabwriter"

	"portprowler/port"
)

// PrintTableFromSlice prints a table from an in-memory slice of results.
// The table does NOT include an OS column (OS is printed separately per-target).
func PrintTableFromSlice(results []port.PortResult, w io.Writer) {
	// sort by protocol, then port number ascending
	sort.Slice(results, func(i, j int) bool {
		// primary: protocol
		if results[i].Proto != results[j].Proto {
			return results[i].Proto < results[j].Proto
		}
		// secondary: port number
		if results[i].Port != results[j].Port {
			return results[i].Port < results[j].Port
		}
		// tertiary tie-breakers for deterministic ordering
		if results[i].IP != results[j].IP {
			return results[i].IP < results[j].IP
		}
		return results[i].Service < results[j].Service
	})

	tw := tabwriter.NewWriter(w, 0, 2, 2, ' ', 0)
	// Removed CONFIDENCE column
	fmt.Fprintln(tw, "TARGET\tIP\tPORT/PROTO\tSTATE\tSERVICE\tINFO")
	for _, r := range results {
		info := r.Error
		if info == "" {
			info = fmt.Sprintf("rtt=%dms", r.RTTMillis)
		}
		target := r.Target
		if target == "" {
			target = r.IP
		}
		fmt.Fprintf(tw, "%s\t%s\t%d/%s\t%s\t%s\t%s\n",
			target, r.IP, r.Port, r.Proto, r.State, r.Service, info)
	}
	_ = tw.Flush()
}

// PrintTable drains the results channel into memory and prints via PrintTableFromSlice.
// This preserves backwards-compatibility with callers that supply a channel.
func PrintTable(results <-chan port.PortResult, w io.Writer) {
	var rs []port.PortResult
	for r := range results {
		rs = append(rs, r)
	}
	PrintTableFromSlice(rs, w)
}
