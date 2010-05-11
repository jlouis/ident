package ident

// TODO:
//   Many things needs some love
//     ; Parsing could be better. Everything should be wrapped in an IdentResponse
//     ; Timeouts are currently not handled.
//     ; There is no system for parallel execution of ident requests. There ought to be.
//

import (
	"bufio"
	"bytes"
	"fmt"
	"net"
	"io"
	"os"
	"strconv"
	"strings"
)

type ProtocolError struct {
	os.ErrorString
}

type IdentResponse struct {
	ServerPort      int
	ClientPort      int
	ResponseTy      string // The type of response, "ERROR", or "USERID"
	Error           string // Is either an identd error message or ""
	UserId          []byte // The Id of the user.
	Valid           bool   // Convenience. True if the USERID was returned, false otherwise
	OperatingSystem string // The Operating system entry
	Charset         string // Character Set of the UserId
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

func idString(sPort int, cPort int) (r []byte) {
	return []byte((string(sPort) + "," + string(cPort)))
}

// Read a line of bytes (up to \n) from b.
// Give up if the line exceeds maxLineLength.
// The returned bytes are a pointer into storage in
// the bufio, so they are only valid until the next bufio read.
func readLineBytes(b *bufio.Reader) (p []byte, err os.Error) {
	if p, err = b.ReadSlice('\n'); err != nil {
		// We always know when EOF is coming.
		// If the caller asked for a line, there should be a line.
		if err == os.EOF {
			err = io.ErrUnexpectedEOF
		}
		return nil, err
	}
	if len(p) >= maxLineLength {
		return nil, ErrLineTooLong
	}

	if p[len(p)-1] != '\r' {
		return nil, ErrNoCR
	}

	// Chop off trailing white space.
	var i int
	for i = len(p); i > 0; i-- {
		if c := p[i-1]; c != ' ' && c != '\r' && c != '\t' && c != '\n' {
			break
		}
	}
	return p[0:i], nil
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
		if (c >= '0' && c <= '9') || c == ' ' || c == '\t' {
			continue
		} else {
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

func parseErrorAddInfo(r *IdentResponse, ai []byte) (*IdentResponse, os.Error) {
	s := strings.TrimSpace(string(ai))
	switch {
	case s == "INVALID-PORT":
		r.Error = "INVALID-PORT"
	case s == "NO-USER":
		r.Error = "NO-USER"
	case s == "HIDDEN-USER":
		r.Error = "HIDDEN-USER"
	case s == "UNKNOWN-ERROR":
		r.Error = "UNKNOWN-ERROR"
	case ai[0] == 'X':
		if len(ai) > 64 {
			return nil, &badStringError{"Token characters too big", string(len(ai))}
		}

		if !allTokenChars(ai) {
			return nil, &badStringError{"Not all characters in token are valid", s}
		}

		r.Error = string(ai)
	default:
		return nil, &badStringError{"Invalid ERROR message", s}
	}

	return r, nil
}

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

func parseUserIdAddInfo(r *IdentResponse, ai []byte) (*IdentResponse, os.Error) {
	ais := bytes.Split(ai, colon, 0)
	if len(ais) < 2 {
		return nil, &badStringError{"Could not split USERID response", string(ai)}
	}

	osc := bytes.Split(ais[0], comma, 0)
	if len(osc) == 2 {
		cs := strings.TrimSpace(string(osc[1]))
		switch cs {
		case "US-ASCII":
			break
		default:
			return nil, &badStringError{"Unknown Character set", string(osc[1])}
		}

		r.Charset = cs
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
		r.UserId = userId
	} else {
		return nil, &badStringError{"Invalid userid detected", ""}
	}

	return r, nil
}

// Parse the type and addInfo sections into an IdentResponse.
func parseType(l []byte, ai []byte, r *IdentResponse) (*IdentResponse, os.Error) {
	s := strings.TrimSpace(string(l))
	switch s {
	case "USERID":
		r.ResponseTy = "USERID"
		r.Valid = true
		return parseUserIdAddInfo(r, ai)
	case "ERROR":
		r.ResponseTy = "ERROR"
		r.Valid = false
		return parseErrorAddInfo(r, ai)
	default:
		return nil, &badStringError{"Cannot parse response Type", s}
	}

	return r, nil
}

func parseResponse(l []byte) (r *IdentResponse, e os.Error) {
	r = new(IdentResponse)
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
func Identify(hostname string, sPort int, cPort int) (*IdentResponse, os.Error) {
	conn, err1 := net.Dial("tcp", "", hostname+":"+string(identPort))
	if err1 != nil {
		return nil, err1
	}
	defer conn.Close()

	conn.Write(idString(sPort, cPort))
	// TODO: 30 sec timeout
	r := bufio.NewReader(conn)
	response, err2 := readLineBytes(r)
	if err2 != nil {
		return nil, err2
	}

	// TODO: Check that the send sPort and cPort are matching
	return parseResponse(response)
}

// vim: set ft=go noexpandtab sw=8 sts=8
