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
	// Basic functionality
	parseResponseTest{query: "6113,23:USERID:UNIX:joe", valid: true, error: false},
	// Extreme ports
	parseResponseTest{query: "00000,80000:USERID:UNIX:joe", valid: true, error: false},
	// Invalid first port
	parseResponseTest{query: "-1,22:USERID:UNIX:joe", valid: false, error: true},
	// Invalid second port
	parseResponseTest{query: "7000,123456:USERID:UNIX:joe", valid: false, error: true},
	// Whitespace in components
	parseResponseTest{query: " 6113	 ,	 23 :USERID:UNIX:joe", valid: true, error: false},

	// Invalid response type
	parseResponseTest{query: " 6113	 ,	 23 :QUUX:UNIX:joe", valid: false, error: true},
	// We do not allow lowercase
	parseResponseTest{query: " 6113	 ,	 23 :userid:UNIX:joe", valid: false, error: true},

	// ERROR INVALID-PORT
	parseResponseTest{query: "80000,22:ERROR:INVALID-PORT", valid: false, error: false},
	// ERROR NO-USER
	parseResponseTest{query: "7000,22: ERROR	:	NO-USER   ", valid: false, error: false},
	// ERROR HIDDEN-USER
	parseResponseTest{query: "80000,22:ERROR:HIDDEN-USER", valid: false, error: false},
	// ERROR UNKNOWN-ERROR
	parseResponseTest{query: "80000,22:ERROR:UNKNOWN-ERROR", valid: false, error: false},

	// Malformed ERROR Response
	parseResponseTest{query: "80000,22:ERROR:Foobar", valid: false, error: true},

	// Non-standard ERROR Response
	parseResponseTest{query: "80000,22:ERROR:XMagicError[[[]]]", valid: false, error: false},

	// Non-standard ERROR Response which is too long (65 chars, including 'X')
	parseResponseTest{query: "80000,22:ERROR:X1234567891234567890123456789012345678901324567890123456789012345",
		valid: false, error: true},

	// USERID UNIX with CHARSET
	parseResponseTest{query: "80000,22: USERID  :UNIX , US-ASCII:joe", valid: true, error: false},
	// USERID OTHER
	parseResponseTest{query: "80000,22: USERID  :OTHER :joe", valid: true, error: false},

	// USERID <token>
	parseResponseTest{query: "80000,22: USERID  :OFFX:joe", valid: true, error: false},
	parseResponseTest{query: "80000,22: USERID  :X1234567891234567890123456789012345678901324567890123456789012345:joe", valid: true, error: true},

	// TODO: Check for too long userid ([512]byte)
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
