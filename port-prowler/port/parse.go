package port

import (
    "errors"
    "sort"
    "strconv"
    "strings"
)

// ParsePortSpec parses a port specification string and returns a sorted, deduplicated slice of ports.
// Supported forms:
//  - single: "22"
//  - list: "22,80,443"
//  - range: "1-1024"
//  - mixed: "22,80,8000-8100"
func ParsePortSpec(spec string) ([]uint16, error) {
    spec = strings.TrimSpace(spec)
    if spec == "" {
        return nil, errors.New("empty port spec")
    }
    seen := make(map[int]struct{})
    parts := strings.Split(spec, ",")
    for _, p := range parts {
        p = strings.TrimSpace(p)
        if p == "" {
            return nil, errors.New("invalid empty token in port spec")
        }
        if strings.Contains(p, "-") {
            bounds := strings.SplitN(p, "-", 2)
            if len(bounds) != 2 {
                return nil, errors.New("invalid range token: " + p)
            }
            start, err := strconv.Atoi(strings.TrimSpace(bounds[0]))
            if err != nil {
                return nil, err
            }
            end, err := strconv.Atoi(strings.TrimSpace(bounds[1]))
            if err != nil {
                return nil, err
            }
            if start < 1 || end < 1 || start > 65535 || end > 65535 {
 				return nil, errors.New("port numbers must be in 1..65535")
 			}
 			if start > end {
 				return nil, errors.New("range start greater than end: " + p)
 			}
			for i := start; i <= end; i++ {
				seen[i] = struct{}{}
			}
		} else {
			v, err := strconv.Atoi(p)
			if err != nil {
				return nil, err
			}
			if v < 1 || v > 65535 {
				return nil, errors.New("port numbers must be in 1..65535")
			}
			seen[v] = struct{}{}
		}
	}
	ports := make([]int, 0, len(seen))
	for p := range seen {
		ports = append(ports, p)
	}
	sort.Ints(ports)
	out := make([]uint16, 0, len(ports))
	for _, p := range ports {
		out = append(out, uint16(p))
	}
	return out, nil
}