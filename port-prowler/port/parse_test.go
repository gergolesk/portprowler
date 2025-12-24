package port

import (
	"reflect"
	"testing"
)

func TestParsePortSpec_Valid(t *testing.T) {
	cases := map[string][]uint16{
		"22":              {22},
		"22,80":           {22, 80},
		"80,22":           {22, 80},
		"1-3":             {1, 2, 3},
		"22,80,8000-8002": {22, 80, 8000, 8001, 8002},
	}
	for spec, want := range cases {
		t.Run(spec, func(t *testing.T) {
			got, err := ParsePortSpec(spec)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("got %v want %v", got, want)
			}
		})
	}
}

func TestParsePortSpec_Invalid(t *testing.T) {
	cases := []string{
		"",        // empty
		"0",       // invalid port
		"65536",   // invalid port
		"10-1",    // reversed range
		"abc",     // bad token
		"22,",     // empty token
		"1-70000", // out of range in range
	}
	for _, spec := range cases {
		t.Run(spec, func(t *testing.T) {
			_, err := ParsePortSpec(spec)
			if err == nil {
				t.Fatalf("expected error for spec %q", spec)
			}
		})
	}
}
