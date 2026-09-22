package e2e

import (
	"bufio"
	"bytes"
	"crypto/md5"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	utls "github.com/refraction-networking/utls"
)

type ja3CaptureResult struct {
	rawClientHello []byte
	ja3            string
	ja3Fingerprint string
	requestURI     string
	serverName     string
	err            error
}

type bufferedConn struct {
	net.Conn
	reader *bytes.Reader
}

func (conn *bufferedConn) Read(p []byte) (int, error) {
	if conn.reader.Len() > 0 {
		return conn.reader.Read(p)
	}
	return conn.Conn.Read(p)
}

func newJA3CaptureTLSServer(t *testing.T) (string, <-chan ja3CaptureResult) {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen on local TCP address: %v", err)
	}
	t.Cleanup(func() {
		listener.Close()
	})

	results := make(chan ja3CaptureResult, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			results <- ja3CaptureResult{err: err}
			return
		}
		defer conn.Close()
		if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
			results <- ja3CaptureResult{err: err}
			return
		}

		rawClientHello, err := readTLSRecord(conn)
		if err != nil {
			results <- ja3CaptureResult{err: err}
			return
		}
		ja3, fingerprint, err := ja3FromRawClientHello(rawClientHello)
		if err != nil {
			results <- ja3CaptureResult{err: err}
			return
		}

		var serverName string
		tlsConn := tls.Server(&bufferedConn{
			Conn:   conn,
			reader: bytes.NewReader(rawClientHello),
		}, &tls.Config{
			Certificates: []tls.Certificate{localTLSCertificate(t)},
			NextProtos:   []string{"http/1.1"},
			GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
				serverName = hello.ServerName
				return nil, nil
			},
		})
		defer tlsConn.Close()

		if err := tlsConn.Handshake(); err != nil {
			results <- ja3CaptureResult{ja3: ja3, ja3Fingerprint: fingerprint, err: err}
			return
		}
		req, err := http.ReadRequest(bufio.NewReader(tlsConn))
		if err != nil {
			results <- ja3CaptureResult{ja3: ja3, ja3Fingerprint: fingerprint, serverName: serverName, err: err}
			return
		}
		_, _ = io.Copy(io.Discard, req.Body)
		_ = req.Body.Close()

		if _, err := io.WriteString(tlsConn, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"); err != nil {
			results <- ja3CaptureResult{ja3: ja3, ja3Fingerprint: fingerprint, serverName: serverName, requestURI: req.URL.RequestURI(), err: err}
			return
		}

		results <- ja3CaptureResult{
			rawClientHello: rawClientHello,
			ja3:            ja3,
			ja3Fingerprint: fingerprint,
			requestURI:     req.URL.RequestURI(),
			serverName:     serverName,
		}
	}()

	return listener.Addr().String(), results
}

func receiveJA3CaptureResult(t *testing.T, results <-chan ja3CaptureResult) ja3CaptureResult {
	t.Helper()

	select {
	case result := <-results:
		return result
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for JA3 capture server")
	}
	return ja3CaptureResult{}
}

func readTLSRecord(conn net.Conn) ([]byte, error) {
	header := make([]byte, 5)
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil, err
	}
	if header[0] != 22 {
		return nil, fmt.Errorf("TLS record type = %d, want handshake", header[0])
	}

	recordLen := int(binary.BigEndian.Uint16(header[3:5]))
	body := make([]byte, recordLen)
	if _, err := io.ReadFull(conn, body); err != nil {
		return nil, err
	}
	return append(header, body...), nil
}

func expectedUTLSJA3Fingerprint(t *testing.T, clientHelloID utls.ClientHelloID, serverName string, nextProtos []string) string {
	t.Helper()

	uconn := utls.UClient(&net.TCPConn{}, &utls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: true,
		NextProtos:         nextProtos,
	}, clientHelloID)
	if err := uconn.BuildHandshakeState(); err != nil {
		t.Fatalf("build %s ClientHello: %v", clientHelloID.Str(), err)
	}

	_, fingerprint, err := ja3FromRawClientHello(prependTLSRecordHeader(uconn.HandshakeState.Hello.Raw))
	if err != nil {
		t.Fatalf("calculate %s JA3: %v", clientHelloID.Str(), err)
	}
	return fingerprint
}

func expectedCryptoTLSJA3Fingerprint(t *testing.T, serverName string, nextProtos []string) string {
	t.Helper()

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()
	deadline := time.Now().Add(2 * time.Second)
	if err := clientConn.SetDeadline(deadline); err != nil {
		t.Fatalf("set client deadline: %v", err)
	}
	if err := serverConn.SetDeadline(deadline); err != nil {
		t.Fatalf("set server deadline: %v", err)
	}

	handshakeDone := make(chan struct{})
	go func() {
		defer close(handshakeDone)
		_ = tls.Client(clientConn, &tls.Config{
			ServerName:         serverName,
			InsecureSkipVerify: true,
			NextProtos:         nextProtos,
		}).Handshake()
	}()

	rawClientHello, err := readTLSRecord(serverConn)
	if err != nil {
		t.Fatalf("read crypto/tls ClientHello: %v", err)
	}
	_, fingerprint, err := ja3FromRawClientHello(rawClientHello)
	if err != nil {
		t.Fatalf("calculate crypto/tls JA3: %v", err)
	}

	serverConn.Close()
	select {
	case <-handshakeDone:
	case <-time.After(2 * time.Second):
		t.Fatal("crypto/tls handshake did not return after server close")
	}
	return fingerprint
}

func prependTLSRecordHeader(handshake []byte) []byte {
	header := []byte{
		22,
		0x03, 0x01,
		byte(len(handshake) >> 8), byte(len(handshake)),
	}
	return append(header, handshake...)
}

func ja3FromRawClientHello(raw []byte) (string, string, error) {
	if len(raw) < 11 {
		return "", "", fmt.Errorf("ClientHello record too short: %d bytes", len(raw))
	}
	if raw[0] != 22 || raw[5] != 1 {
		return "", "", fmt.Errorf("record is not a TLS ClientHello")
	}

	spec, err := (&utls.Fingerprinter{AllowBluntMimicry: true}).FingerprintClientHello(raw)
	if err != nil {
		return "", "", err
	}

	version := binary.BigEndian.Uint16(raw[9:11])
	wireExtensions, err := wireJA3ExtensionIDs(raw)
	if err != nil {
		return "", "", err
	}
	ja3 := strings.Join([]string{
		strconv.Itoa(int(version)),
		joinJA3Uint16s(spec.CipherSuites),
		joinJA3Uint16s(wireExtensions),
		joinJA3CurveIDs(spec.Extensions),
		joinJA3PointFormats(spec.Extensions),
	}, ",")
	sum := md5.Sum([]byte(ja3))
	return ja3, hex.EncodeToString(sum[:]), nil
}

// Inspect the serialized extension list: reserializing a uTLS padding object
// can drop it, even though extension 21 was actually present on the wire.
func wireJA3ExtensionIDs(raw []byte) ([]uint16, error) {
	if len(raw) < 44 {
		return nil, io.ErrUnexpectedEOF
	}
	pos := 44 + int(raw[43])
	if pos+2 > len(raw) {
		return nil, io.ErrUnexpectedEOF
	}
	pos += 2 + int(binary.BigEndian.Uint16(raw[pos:pos+2]))
	if pos >= len(raw) {
		return nil, io.ErrUnexpectedEOF
	}
	pos += 1 + int(raw[pos])
	if pos == len(raw) {
		return nil, nil
	}
	if pos+2 > len(raw) {
		return nil, io.ErrUnexpectedEOF
	}
	end := pos + 2 + int(binary.BigEndian.Uint16(raw[pos:pos+2]))
	pos += 2
	if end > len(raw) {
		return nil, io.ErrUnexpectedEOF
	}
	ids := []uint16{}
	for pos < end {
		if pos+4 > end {
			return nil, io.ErrUnexpectedEOF
		}
		ids = append(ids, binary.BigEndian.Uint16(raw[pos:pos+2]))
		pos += 4 + int(binary.BigEndian.Uint16(raw[pos+2:pos+4]))
		if pos > end {
			return nil, io.ErrUnexpectedEOF
		}
	}
	return ids, nil
}

func joinJA3Uint16s(values []uint16) string {
	parts := make([]string, 0, len(values))
	for _, value := range values {
		if isJA3GREASE(value) {
			continue
		}
		parts = append(parts, strconv.Itoa(int(value)))
	}
	return strings.Join(parts, "-")
}

func joinJA3CurveIDs(extensions []utls.TLSExtension) string {
	for _, extension := range extensions {
		curves, ok := extension.(*utls.SupportedCurvesExtension)
		if !ok {
			continue
		}

		values := make([]uint16, 0, len(curves.Curves))
		for _, curve := range curves.Curves {
			values = append(values, uint16(curve))
		}
		return joinJA3Uint16s(values)
	}
	return ""
}

func joinJA3PointFormats(extensions []utls.TLSExtension) string {
	for _, extension := range extensions {
		points, ok := extension.(*utls.SupportedPointsExtension)
		if !ok {
			continue
		}

		parts := make([]string, 0, len(points.SupportedPoints))
		for _, point := range points.SupportedPoints {
			parts = append(parts, strconv.Itoa(int(point)))
		}
		return strings.Join(parts, "-")
	}
	return ""
}

func ja3ExtensionIDs(extensions []utls.TLSExtension) []uint16 {
	ids := make([]uint16, 0, len(extensions))
	for _, extension := range extensions {
		id, ok := ja3ExtensionID(extension)
		if ok && !isJA3GREASE(id) {
			ids = append(ids, id)
		}
	}
	return ids
}

func ja3ExtensionID(extension utls.TLSExtension) (uint16, bool) {
	if extension.Len() >= 2 {
		buf := make([]byte, extension.Len())
		n, _ := extension.Read(buf)
		if n >= 2 {
			return binary.BigEndian.Uint16(buf[:2]), true
		}
	}

	switch extension.(type) {
	case *utls.SNIExtension:
		return 0, true
	default:
		return 0, false
	}
}

func isJA3GREASE(value uint16) bool {
	high := byte(value >> 8)
	low := byte(value)
	return value == utls.GREASE_PLACEHOLDER || high == low && high&0x0f == 0x0a
}
