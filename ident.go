package ident

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

// The Error type for an error in the protocol
type ProtocolError struct {
	Err error
}

// Response is the structure of an ident response.
type Response struct {
	ServerPort      int    // Port of the server
	ClientPort      int    // Port of the client
	Error           string // Is either an identd error message or ""
	UserId          string // The Id of the user.
	OperatingSystem string // The Operating system entry
}

const (
	maxLineLength = 1000 // assumed ≤ bufio.defaultBufSize
	identPort     = 113  // Default port for the ident server
)

var (
	// Possible errors
	ErrLineTooLong = errors.New("response line too long")
	ErrNoCR        = errors.New("no CR character found before LF")
)

var (
	// Notions of token symbols we want to split on
	colon = []byte{':'}
	comma = []byte{','}
)

// IsValid checks if the response is valid
func (r Response) IsValid() bool {
	return (r.Error != "")
}

// badStringError is an internal error type
type badStringError struct {
	what string
	str  string
}

func (e *badStringError) Error() string {
	return fmt.Sprintf("%s %q", e.what, e.str)
}

// The string to send to the ident server
func idString(sPort int, cPort int) (r []byte) {
	return []byte((string(sPort) + "," + string(cPort)))
}

// readLineBytes reads \r\n terminated lines from a Reader
// gives up if the line exceeds maxLineLength.
// The returned bytes are a pointer into storage in
// the bufio, so they are only valid until the next bufio read.
func readLineBytes(b *bufio.Reader) (p []byte, err error) {
	if p, err = b.ReadSlice('\n'); err != nil {
		return nil, err
	}
	if len(p) >= maxLineLength {
		return nil, ErrLineTooLong
	}

	if p[len(p)-1] != '\r' {
		return nil, ErrNoCR
	}

	// Chop off trailing CR
	p = p[0 : len(p)-1]
	if len(p) > 0 && p[len(p)-1] == '\r' {
		p = p[0 : len(p)-1]
	}

	return p, nil
}

// readLine is like readLineBytes, but converts the bytes into a string.
func readLine(b *bufio.Reader) (s string, err error) {
	p, e := readLineBytes(b)
	if e != nil {
		return "", e
	}
	return string(p), nil
}

// parsePort parses the port-id component of the response.
// According to RFC1413 a valid port number is one to five 'digit' characters. 
// No kind of checking is made to make sure it is a TCP port number. 
// '99999' is a valid response as a result. We will check that the response matches the
// query in another place.
func parsePort(l []byte) (int, error) {
	for _, c := range l {
		if c != ' ' && c != '\t' && (c < '0' || c > '9') {
			return 0, &badStringError{"Port value not all digits", string(l)}
		}
	}
	s := strings.TrimSpace(string(l))

	if len(s) > 5 {
		return 0, &badStringError{"Port value too long", string(l)}
	}

	p, e := strconv.Atoi(s)
	if e != nil {
		return 0, e
	}

	return p, nil
}

// allTokenChars predicates if the input is valid tokens in Ident type 'X' responses
func allTokenChars(ai []byte) bool {
	ba := []byte("-, .:!@#$%^&*()_=+.,<>/?\"'~`{}[];")
	for _, c := range ai {
		switch {
		case c >= 'A' && c <= 'Z':
			continue
		case c >= 'a' && c <= 'z':
			continue
		default:
			if bytes.Index(ba, []byte{c}) < 0 {
				return false
			}

			continue
		}
	}

	return true
}

// parseErrorAddInfo parses ERROR messages and the additional info block
func parseErrorAddInfo(r *Response, ai []byte) (*Response, error) {
	s := strings.TrimSpace(string(ai))
	switch s {
	case "INVALID-PORT", "NO-USER", "HIDDEN-USER", "UNKNOWN-ERROR":
		r.Error = s
	default:
		if ai[0] == 'X' {
			if len(ai) > 64 {
				return nil, &badStringError{"Token characters too big",
					string(len(ai))}
			}

			if !allTokenChars(ai) {
				return nil, &badStringError{
					"Not all characters in token are valid", s}
			}

			r.Error = string(ai)
		} else {
			return nil, &badStringError{"Invalid ERROR message", s}
		}
	}

	return r, nil
}

// validUserId is a predicate function for the valid user
func validUserId(userId []byte) bool {
	if len(userId) > 512 {
		return false
	}

	for _, c := range userId {
		switch c {
		case 0, 12, 15:
			return false
		}
	}

	return true
}

// parseUserId parses the USERID portion, and additionally the info block
func parseUserIdAddInfo(r *Response, ai []byte) (*Response, error) {
	ais := bytes.Split(ai, colon)
	if len(ais) < 2 {
		return nil, &badStringError{"Could not split USERID response", string(ai)}
	}

	osc := bytes.Split(ais[0], comma)
	if len(osc) == 2 {
		cs := strings.TrimSpace(string(osc[1]))
		switch cs {
		case "US-ASCII", "UTF-8", "utf-8":
			break
		default:
			return nil, &badStringError{"Unknown Character set", string(osc[1])}
		}
	}

	if len(osc) >= 1 {
		os := strings.TrimSpace(string(osc[0]))
		switch os {
		case "UNIX", "OTHER":
			break
		default:
			if len(osc[0]) > 64 {
				return nil, &badStringError{"Token characters too big",
					string(len(ai))}
			}

			if !allTokenChars(osc[0]) {
				return nil, &badStringError{"Not all characters in token are valid", ""}
			}

		}

		r.OperatingSystem = os
	} else {
		return nil, &badStringError{"Could not parse opsys-charset", string(ai)}
	}

	userId := ais[1]
	if validUserId(userId) {
		r.UserId = string(userId)
	} else {
		return nil, &badStringError{"Invalid userid detected", ""}
	}

	return r, nil
}

// parseType parses the type and the additional Info sections
func parseType(l []byte, ai []byte, r *Response) (*Response, error) {
	s := strings.TrimSpace(string(l))
	switch s {
	case "USERID":
		return parseUserIdAddInfo(r, ai)
	case "ERROR":
		return parseErrorAddInfo(r, ai)
	default:
		return nil, &badStringError{"Cannot parse response Type", s}
	}

	return r, nil
}

// parseResponse parses responses from byte sequences into Response objects
func parseResponse(l []byte) (r *Response, e error) {
	r = new(Response)
	// Parse Server Port
	bs := bytes.SplitN(l, comma, 2)
	if len(bs) < 2 {
		goto Malformed
	}
	r.ServerPort, e = parsePort(bs[0])
	if e != nil {
		return nil, e
	}

	// Parse Client port
	bs = bytes.SplitN(bs[1], colon, 2)
	if len(bs) < 2 {
		goto Malformed
	}
	r.ClientPort, e = parsePort(bs[0])
	if e != nil {
		return nil, e
	}

	// Parse response type
	bs = bytes.SplitN(bs[1], colon, 2)
	if len(bs) < 2 {
		goto Malformed
	}
	r, e = parseType(bs[0], bs[1], r)
	if e != nil {
		return nil, e
	}

	return r, nil

Malformed:
	return nil, &badStringError{"Malformed ident parse", string(l)}
}

// Query makes ident queries to foreign servers
// Make a connection to host asking for an iden on the server port sPort and client port cPort.
// For example, if we have a connection from host B to host A where B's port is 6113 and A's
// port is 23 (A telnet connection from client B to server A), then the A host must ask B with
// sPort = 6113 and cPort = 23. In other words, sPort is the machine the identd server is
// running on.
//
// The function returns the source port reflected on the server, the destination port reflected
// on the server and an IdentResponse struct containing the ident information.
func Query(hostname string, sPort int, cPort int) (*Response, error) {

	duration, err0 := time.ParseDuration("30s")
	if err0 != nil {
		return nil, err0
	}

	conn, err1 := net.Dial("tcp", hostname+":"+string(identPort))
	if err1 != nil {
		return nil, err1
	}
	defer conn.Close()

	idS := idString(sPort, cPort)
	conn.SetDeadline(time.Now().Add(duration))
	if _, e := conn.Write(idS); e != nil {
		return nil, e
	}

	r := bufio.NewReader(conn)
	conn.SetDeadline(time.Now().Add(duration))
	response, err2 := readLineBytes(r)
	if err2 != nil {
		return nil, err2
	}

	resp, e := parseResponse(response)
	if e != nil {
		return nil, e
	}

	if resp.ServerPort != sPort || resp.ClientPort != cPort {
		return nil, &badStringError{"Source and Client port mismatch", ""}
	}

	return resp, nil
}

// vim: set ft=go noexpandtab sw=8 sts=8
