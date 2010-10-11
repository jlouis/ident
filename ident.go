package ident

import (
	"bufio"
	"bytes"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
)

type ProtocolError struct {
	os.ErrorString
}

type Validity interface {
	Valid() bool
}

// The response object of an ident request.
type Response struct {
	ServerPort      int
	ClientPort      int
	Error           string // Is either an identd error message or ""
	UserId          string // The Id of the user.
	OperatingSystem string // The Operating system entry
}

func (r Response) Valid() bool {
	return (r.Error != "")
}

const (
	maxLineLength = 1000 // assumed <= bufio.defaultBufSize
	identPort     = 113
)

var (
	ErrLineTooLong = &ProtocolError{"response line too long"}
	ErrNoCR        = &ProtocolError{"no CR character found before LF"}
)

type badStringError struct {
	what string
	str  string
}

func (e *badStringError) String() string {
	return fmt.Sprintf("%s %q", e.what, e.str)
}

// The string to send to the ident server
func idString(sPort int, cPort int) (r []byte) {
	return []byte((string(sPort) + "," + string(cPort)))
}

// Read a line of bytes (up to \r\n) from b.
// Give up if the line exceeds maxLineLength.
// The returned bytes are a pointer into storage in
// the bufio, so they are only valid until the next bufio read.
func readLineBytes(b *bufio.Reader) (p []byte, err os.Error) {
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

// readLineBytes, but convert the bytes into a string.
func readLine(b *bufio.Reader) (s string, err os.Error) {
	p, e := readLineBytes(b)
	if e != nil {
		return "", e
	}
	return string(p), nil
}

var (
	colon = []byte{':'}
	comma = []byte{','}
)

// Parse a port-id component of the response. According to RFC1413 a valid port number is
// one to five 'digit' characters. No kind of checking is made to make sure it is a TCP
// port number. '99999' is a valid response as a result. We will check that the response
// matches the query in another place.
func parsePort(l []byte) (int, os.Error) {
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

// Predicate function. Only allow valid tokens in Ident type 'X' responses
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

// If the message is an ERROR message, parse the Additional info block of the Error
func parseErrorAddInfo(r *Response, ai []byte) (*Response, os.Error) {
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

// Predicate function: return true on a valid user id, false otherwise.
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

// If the response type is USERID, parse the additional info block
func parseUserIdAddInfo(r *Response, ai []byte) (*Response, os.Error) {
	ais := bytes.Split(ai, colon, -1)
	if len(ais) < 2 {
		return nil, &badStringError{"Could not split USERID response", string(ai)}
	}

	osc := bytes.Split(ais[0], comma, -1)
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

// Parse the type and addInfo sections into an IdentResponse.
func parseType(l []byte, ai []byte, r *Response) (*Response, os.Error) {
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

// Response parser. Given a byte slice, it parses the slice for the RFC1413 protocol and then
// fills the result into the IdentResponse object returned.
func parseResponse(l []byte) (r *Response, e os.Error) {
	r = new(Response)
	// Parse Server Port
	bs := bytes.Split(l, comma, 2)
	if len(bs) < 2 {
		goto Malformed
	}
	r.ServerPort, e = parsePort(bs[0])
	if e != nil {
		return nil, e
	}

	// Parse Client port
	bs = bytes.Split(bs[1], colon, 2)
	if len(bs) < 2 {
		goto Malformed
	}
	r.ClientPort, e = parsePort(bs[0])
	if e != nil {
		return nil, e
	}

	// Parse response type
	bs = bytes.Split(bs[1], colon, 2)
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

// Make a connection to host asking for an iden on the server port sPort and client port cPort.
// For example, if we have a connection from host B to host A where B's port is 6113 and A's
// port is 23 (A telnet connection from client B to server A), then the A host must ask B with
// sPort = 6113 and cPort = 23. In other words, sPort is the machine the identd server is
// running on.
//
// The function returns the source port reflected on the server, the destination port reflected
// on the server and an IdentResponse struct containing the ident information.
func Query(hostname string, sPort int, cPort int) (*Response, os.Error) {
	conn, err1 := net.Dial("tcp", "", hostname+":"+string(identPort))
	if err1 != nil {
		return nil, err1
	}
	defer conn.Close()
	conn.SetTimeout(30000 * 1000000)

	idS := idString(sPort, cPort)
	if _, e := conn.Write(idS); e != nil {
		return nil, e
	}

	r := bufio.NewReader(conn)
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
