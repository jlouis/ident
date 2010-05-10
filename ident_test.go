// Tests for ident.go

package ident

import (
	"testing"
)

type parseResponseTest struct {
	query string
	valid bool
	error bool
}

var parseResponseTests = []parseResponseTest{
	parseResponseTest{query: "6113,23:USERID:UNIX:joe", valid: true, error: false},
	parseResponseTest{query: "0,23:USERID:UNIX:joe", valid: true, error: false},
	parseResponseTest{query: "7890,22:USERID:OTHER:foo   ", valid: true, error: false},
	// This next one is valid according to spec.
	parseResponseTest{query: "80000,22:ERROR:INVALID-PORT", valid: false, error: false},
	parseResponseTest{query: "-1,22:USERID:UNIX:joe", valid: false, error: true},
	parseResponseTest{query: "00000:22:USERID:UNIX:joe", valid: true, error: false},
	parseResponseTest{query: "40000,65536:USERID:UNIX:joe", valid: false, error: true},
	parseResponseTest{query: "40000,-234:USERID:UNIX:joe", valid: false, error: true},
	parseResponseTest{query: "6113,23:ERROR:NO-USER", valid: false, error: false},
}

func TestParseResponse(t *testing.T) {
	for i, test := range parseResponseTests {
		q, err := parseResponse([]byte(test.query))
		if !test.error && err != nil {
			t.Errorf("test %d: Unexpected error: %v", i, err)
		}
		if test.error && err == nil {
			t.Errorf("test %d should have returned error", i)
		}
		if q != nil && q.Valid != test.valid {
			t.Errorf("test %d does not agree on validity", i)
		}
	}
}

// vim: set ft=go noexpandtab sw=8 sts=8
