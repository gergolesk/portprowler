package output

import (
	"fmt"
	"io"
	"text/tabwriter"

	"portprowler/port"
)

// PrintTable consumes results channel and prints a human-readable table to writer.
func PrintTable(results <-chan port.PortResult, w io.Writer) {
	tw := tabwriter.NewWriter(w, 0, 2, 2, ' ', 0)
	// add OS and CONFIDENCE columns
	fmt.Fprintln(tw, "TARGET\tIP\tPORT/PROTO\tSTATE\tSERVICE\tOS\tCONFIDENCE\tINFO")
	for r := range results {
		info := r.Error
		if info == "" {
			info = fmt.Sprintf("rtt=%dms", r.RTTMillis)
		}
		target := r.Target
		if target == "" {
			target = r.IP
		}
		// include OS and Confidence in the output row
		fmt.Fprintf(tw, "%s\t%s\t%d/%s\t%s\t%s\t%s\t%s\t%s\n",
			target, r.IP, r.Port, r.Proto, r.State, r.Service, r.OSGuess, r.Confidence, info)
	}
	_ = tw.Flush()
}
