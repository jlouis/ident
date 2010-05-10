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
	parseResponseTest{query: "6113,23:ERROR:NO-USER", valid: false, error: false},
}

func TestParseResponse(t *testing.T) {
	for i, test := range parseResponseTests {
		q, err := ParseResponse([]byte(test.query))
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
