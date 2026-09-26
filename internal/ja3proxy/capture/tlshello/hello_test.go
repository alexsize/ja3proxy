package tlshello

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"reflect"
	"strings"
	"testing"
	"time"
)

func vector16(b []byte) []byte { return append([]byte{byte(len(b) >> 8), byte(len(b))}, b...) }
func extension(id uint16, b []byte) []byte {
	return append([]byte{byte(id >> 8), byte(id)}, vector16(b)...)
}
func fixture(ext []byte) []byte {
	b := []byte{3, 3}
	b = append(b, make([]byte, 32)...)
	b = append(b, 0, 0, 2, 0x13, 1, 1, 0)
	b = append(b, vector16(ext)...)
	return append([]byte{1, byte(len(b) >> 16), byte(len(b) >> 8), byte(len(b))}, b...)
}
func record(b []byte) []byte { return append([]byte{22, 3, 1, byte(len(b) >> 8), byte(len(b))}, b...) }

func TestGoldenMinimal(t *testing.T) {
	raw := fixture(nil)
	h, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	fp, err := Calculate(h, raw, record(raw))
	if err != nil {
		t.Fatal(err)
	}
	if fp.JA3 != "771,4865,,," || fp.JA3Hash != "ea1e247991e541e39bf918cb7cfa5139" {
		t.Fatalf("JA3 golden: %+v", fp)
	}
	if fp.JA4 != "t12i010000_0f2cb44170f4_000000000000" {
		t.Fatal(fp.JA4)
	}
	const norm = `{"ciphers":[4865],"compression_methods":[0],"extensions":[],"legacy_version":771,"session_id_length":0}`
	if string(fp.Normalized) != norm || fp.NormalizedSHA256 != "43a11d0e4c85f03ceaf8207a3e4af2c1b14fa82196fd0f0800fab09c2079f454" {
		t.Fatalf("normalization golden: %s %s", fp.Normalized, fp.NormalizedSHA256)
	}
}

func TestJA4PublishedVector(t *testing.T) {
	// Independent algorithm vector from FoxIO technical_details/JA4.md.
	h := &Hello{LegacyVersion: 0x0303, SupportedVersions: []uint16{0x0a0a, 0x0304}, CipherSuites: []uint16{0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035}, ALPN: []string{"6832"}, SignatureAlgorithms: []uint16{0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601}}
	for _, id := range []uint16{0x001b, 0, 0x0033, 0x0010, 0x4469, 0x0017, 0x002d, 0x000d, 0x0005, 0x0023, 0x0012, 0x002b, 0xff01, 0x000b, 0x000a, 0x0015} {
		fields := map[string]any{}
		if id == 51 {
			fields["shares"] = []any{}
		}
		h.Extensions = append(h.Extensions, Extension{ID: id, Fields: fields})
	}
	fp, err := Calculate(h, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if fp.JA4 != "t13d1516h2_8daaf6152771_e5627efa2ab1" {
		t.Fatal(fp.JA4)
	}
}

func TestReassemblyEveryBoundary(t *testing.T) {
	raw := fixture(nil)
	for recordSplit := 1; recordSplit < len(raw); recordSplit++ {
		wire := append(record(raw[:recordSplit]), record(raw[recordSplit:])...)
		for tcpSplit := 0; tcpSplit <= len(wire); tcpSplit++ {
			s := NewStream(DefaultLimits())
			s.Feed(wire[:tcpSplit])
			s.Feed(wire[tcpSplit:])
			c := s.Finish("closed")
			if c.Status != "complete" || !bytes.Equal(c.Raw, raw) || !bytes.Equal(c.Records, wire) {
				t.Fatalf("record=%d TCP=%d: %+v", recordSplit, tcpSplit, c)
			}
		}
	}
	s := NewStream(DefaultLimits())
	for _, b := range record(raw) {
		s.Feed([]byte{b})
	}
	if s.Finish("closed").Status != "complete" {
		t.Fatal("one-byte reads")
	}
}

func TestMalformedAndLimits(t *testing.T) {
	raw := fixture(nil)
	for i := 0; i < len(raw); i++ {
		if _, err := Parse(raw[:i]); err == nil {
			t.Fatalf("accepted truncated %d", i)
		}
	}
	if _, err := Parse(append(append([]byte(nil), raw...), 0)); err == nil {
		t.Fatal("accepted trailing data")
	}
	cases := []struct {
		name   string
		wire   []byte
		limits Limits
		status string
	}{
		{"notTLS", []byte("GET / HTTP/1.1"), Limits{}, "not_tls"},
		{"oversizedRecord", []byte{22, 3, 3, 0xff, 0xff}, Limits{}, "truncated"},
		{"oversizedHello", record([]byte{1, 0xff, 0xff, 0xff}), Limits{}, "truncated"},
		{"wrongHandshake", record([]byte{2, 0, 0, 0}), Limits{}, "malformed"},
		{"zeroRecord", []byte{22, 3, 3, 0, 0}, Limits{}, "malformed"},
		{"badVersion", []byte{22, 9, 9, 0, 2}, Limits{}, "malformed"},
		{"recordCount", append(record(raw[:2]), record(raw[2:])...), Limits{MaxRecords: 1}, "truncated"},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			s := NewStream(tt.limits)
			s.Feed(tt.wire)
			if got := s.Finish("closed").Status; got != tt.status {
				t.Fatal(got)
			}
		})
	}
}

func TestNormalizationDynamicAndUnknown(t *testing.T) {
	key := append([]byte{0, 29}, vector16(bytes.Repeat([]byte{0xaa}, 32))...)
	ext := append(extension(51, vector16(key)), extension(0xaaaa, []byte{1, 2})...)
	ext = append(ext, extension(0xaaaa, []byte{3, 4})...)
	a := fixture(ext)
	b := append([]byte(nil), a...)
	b[6] = 0xff
	// Change key bytes only, preserving structure.
	index := bytes.Index(b, bytes.Repeat([]byte{0xaa}, 32))
	b[index] = 0xbb
	ah, err := Parse(a)
	if err != nil {
		t.Fatal(err)
	}
	bh, err := Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	af, _ := Calculate(ah, a, record(a))
	bf, _ := Calculate(bh, b, record(b))
	if af.RawSHA256 == bf.RawSHA256 || af.NormalizedSHA256 != bf.NormalizedSHA256 {
		t.Fatal("dynamic values were not normalized")
	}
	if len(ah.Extensions) != 3 || ah.Extensions[1].Position != 1 || ah.Extensions[2].Position != 2 {
		t.Fatal("duplicate extension lost")
	}
	if strings.Contains(string(af.Normalized), strings.Repeat("aa", 32)) {
		t.Fatal("public key retained")
	}
}

func TestParseExtensionVectorsAndPrivacy(t *testing.T) {
	sni := extension(0, vector16(append([]byte{0}, vector16([]byte("test.example"))...)))
	ext := append(sni, extension(16, vector16([]byte{2, 'h', '2', 8, 'h', 't', 't', 'p', '/', '1', '.', '1'}))...)
	ext = append(ext, extension(10, vector16([]byte{0x0a, 0x0a, 0, 29, 0, 23}))...)
	ext = append(ext, extension(43, []byte{4, 3, 4, 3, 3})...)
	ext = append(ext, extension(13, vector16([]byte{4, 3, 8, 4}))...)
	ext = append(ext, extension(35, []byte("CANARY_SESSION_TICKET"))...)
	ext = append(ext, extension(65037, []byte{1, 2, 3})...)
	h, err := Parse(fixture(ext))
	if err != nil {
		t.Fatal(err)
	}
	if h.ServerName != "test.example" || !reflect.DeepEqual(h.ALPN, []string{"6832", "687474702f312e31"}) || !h.ECH {
		t.Fatalf("%+v", h)
	}
	data, _ := json.Marshal(h)
	if bytes.Contains(data, []byte("CANARY")) || bytes.Contains(data, []byte(hex.EncodeToString([]byte("CANARY_SESSION_TICKET")))) {
		t.Fatal("ticket leaked")
	}
	for _, bad := range [][]byte{extension(10, []byte{0, 3, 0}), extension(16, []byte{0, 1, 0}), extension(51, []byte{0, 4, 0, 29, 0, 99})} {
		if _, err := Parse(fixture(bad)); err == nil {
			t.Fatal("malformed extension accepted")
		}
	}
}

type stubConn struct {
	net.Conn
	written  []byte
	maxWrite int
	writeErr error
	input    *bytes.Reader
}

func (c *stubConn) Write(p []byte) (int, error) {
	n := len(p)
	if c.maxWrite > 0 {
		n = min(n, c.maxWrite)
	}
	c.written = append(c.written, p[:n]...)
	return n, c.writeErr
}
func (c *stubConn) Read(p []byte) (int, error)      { return c.input.Read(p) }
func (c *stubConn) Close() error                    { return nil }
func (c *stubConn) SetReadDeadline(time.Time) error { return nil }

func TestRecordingConnShortWrites(t *testing.T) {
	wire := record(fixture(nil))
	under := &stubConn{maxWrite: 3}
	captures := []Capture{}
	c := Wrap(under, false, Limits{}, func(v Capture) { captures = append(captures, v) })
	for rest := wire; len(rest) > 0; {
		n, err := c.Write(rest)
		if err != nil {
			t.Fatal(err)
		}
		rest = rest[n:]
	}
	under.maxWrite = 0
	c.Write([]byte("not captured"))
	c.Close()
	if len(captures) != 1 || captures[0].Status != "complete" || !bytes.Equal(captures[0].Records, wire) {
		t.Fatalf("%+v", captures)
	}
	if !bytes.Equal(under.written, append(wire, []byte("not captured")...)) {
		t.Fatal("wire changed")
	}
	errWrite := errors.New("write failure")
	under = &stubConn{maxWrite: 7, writeErr: errWrite}
	captures = nil
	c = Wrap(under, false, Limits{}, func(v Capture) { captures = append(captures, v) })
	n, err := c.Write(wire)
	if n != 7 || err != errWrite || len(captures) != 1 || captures[0].Status == "complete" {
		t.Fatal("partial failed write misrepresented")
	}
}

func TestRecordingConnCapturesSecondClientHello(t *testing.T) {
	wire := append(record(fixture(nil)), record(fixture(nil))...)
	under := &stubConn{}
	captures := make([]Capture, 0, 2)
	c := Wrap(under, false, Limits{}, func(v Capture) { captures = append(captures, v) })
	if n, err := c.Write(wire); err != nil || n != len(wire) {
		t.Fatalf("write = %d/%v", n, err)
	}
	c.Close()
	if len(captures) != 2 {
		t.Fatalf("captures = %d, want 2", len(captures))
	}
	for index, capture := range captures {
		if capture.Status != "complete" || capture.HandshakeSequence != index+1 || !bytes.Equal(capture.Raw, fixture(nil)) {
			t.Fatalf("capture %d = %+v", index, capture)
		}
	}
}

func TestRecordingConnCapturesSecondClientHelloAfterCompatibilityCCS(t *testing.T) {
	first := record(fixture(nil))
	ccs := []byte{20, 3, 3, 0, 1, 1}
	second := record(fixture(nil))
	wire := append(append(append([]byte(nil), first...), ccs...), second...)
	for split := len(first); split <= len(first)+len(ccs)+5; split++ {
		under := &stubConn{}
		var captures []Capture
		conn := Wrap(under, false, Limits{}, func(capture Capture) { captures = append(captures, capture) })
		if _, err := conn.Write(wire[:split]); err != nil {
			t.Fatal(err)
		}
		if _, err := conn.Write(wire[split:]); err != nil {
			t.Fatal(err)
		}
		_ = conn.Close()
		if len(captures) != 2 || captures[0].Status != "complete" || captures[1].Status != "complete" || captures[1].HandshakeSequence != 2 {
			t.Fatalf("split %d: captures = %+v", split, captures)
		}
	}
}

func TestRecordingConnDoesNotInventClientHelloAfterCompatibilityCCS(t *testing.T) {
	first := record(fixture(nil))
	ccs := []byte{20, 3, 3, 0, 1, 1}
	for _, suffix := range [][]byte{
		ccs,
		append(append([]byte(nil), ccs...), 23, 3, 3, 0, 1, 0),
		{22, 3, 3, 0, 4, 11, 0, 0, 0}, // A different TLS handshake message.
	} {
		under := &stubConn{}
		var captures []Capture
		conn := Wrap(under, false, Limits{}, func(capture Capture) { captures = append(captures, capture) })
		if _, err := conn.Write(append(append([]byte(nil), first...), suffix...)); err != nil {
			t.Fatal(err)
		}
		_ = conn.Close()
		if len(captures) != 1 || captures[0].Status != "complete" {
			t.Fatalf("suffix %v: captures = %+v", suffix, captures)
		}
	}
	under := &stubConn{input: bytes.NewReader(append(append([]byte(nil), first...), ccs...))}
	var readCaptures []Capture
	conn := Wrap(under, true, Limits{}, func(capture Capture) { readCaptures = append(readCaptures, capture) })
	if _, err := io.ReadAll(conn); err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
	if len(readCaptures) != 1 || readCaptures[0].Status != "complete" {
		t.Fatalf("read/EOF captures = %+v", readCaptures)
	}
}

func TestSniffReplayAndTimeout(t *testing.T) {
	for _, wire := range [][]byte{record(fixture(nil)), []byte("hello world"), []byte{22, 3}} {
		base := &stubConn{input: bytes.NewReader(wire)}
		conn, _, err := Sniff(base, time.Second, Limits{})
		if err != nil {
			t.Fatal(err)
		}
		got, err := io.ReadAll(conn)
		if err != nil || !bytes.Equal(wire, got) {
			t.Fatal("sniff lost bytes")
		}
	}
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	_, c, err := Sniff(a, 5*time.Millisecond, Limits{})
	if err != nil || c.Status != "timeout" {
		t.Fatalf("%+v %v", c, err)
	}
}

func FuzzParse(f *testing.F) {
	f.Add(fixture(nil))
	f.Add([]byte{1, 0, 0, 0})
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > MaxHelloSize {
			return
		}
		h, err := Parse(b)
		if err == nil {
			if _, err := Calculate(h, b, record(b)); err != nil {
				t.Fatal(err)
			}
		}
	})
}

func FuzzStream(f *testing.F) {
	f.Add(record(fixture(nil)), uint16(7))
	f.Add([]byte{22, 3, 3, 0, 1, 1}, uint16(1))
	f.Fuzz(func(t *testing.T, b []byte, chunk uint16) {
		s := NewStream(Limits{})
		step := int(chunk)%1024 + 1
		for len(b) > 0 {
			n := min(step, len(b))
			s.Feed(b[:n])
			b = b[n:]
			if s.Done() {
				break
			}
		}
		c := s.Finish("closed")
		if len(c.Raw) > MaxHelloSize || len(c.Records) > MaxHelloSize+18432+64*5 {
			t.Fatal("unbounded capture")
		}
	})
}

func BenchmarkReassembly(b *testing.B) {
	wire := record(fixture(nil))
	b.ReportAllocs()
	for b.Loop() {
		s := NewStream(Limits{})
		s.Feed(wire)
		s.Finish("closed")
	}
}

type benchmarkConn struct{}

func (benchmarkConn) Read([]byte) (int, error)         { return 0, io.EOF }
func (benchmarkConn) Write(value []byte) (int, error)  { return len(value), nil }
func (benchmarkConn) Close() error                     { return nil }
func (benchmarkConn) LocalAddr() net.Addr              { return nil }
func (benchmarkConn) RemoteAddr() net.Addr             { return nil }
func (benchmarkConn) SetDeadline(time.Time) error      { return nil }
func (benchmarkConn) SetReadDeadline(time.Time) error  { return nil }
func (benchmarkConn) SetWriteDeadline(time.Time) error { return nil }

func BenchmarkRecordingConnOnOff(b *testing.B) {
	wire := record(fixture(nil))
	b.ReportAllocs()
	b.Run("recorder_off", func(b *testing.B) {
		conn := benchmarkConn{}
		for b.Loop() {
			_, _ = conn.Write(wire)
		}
	})
	b.Run("recorder_on", func(b *testing.B) {
		conn := benchmarkConn{}
		for b.Loop() {
			wrapped := Wrap(conn, false, DefaultLimits(), func(Capture) {})
			_, _ = wrapped.Write(wire)
		}
	})
}

func TestPSKIdentityRedaction(t *testing.T) {
	ident := append(vector16([]byte("SECRET_TICKET")), 0, 0, 0, 42)
	psk := append(vector16(ident), vector16(append([]byte{32}, bytes.Repeat([]byte{0xab}, 32)...))...)
	raw := fixture(append(extension(41, psk), extension(42, nil)...))
	h, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	fp, _ := Calculate(h, raw, record(raw))
	if h.HandshakeType != HandshakeTypePSK || !h.SessionResumption || !h.PSKPresent || h.PSKIdentityCount != 1 || !h.EarlyData {
		t.Fatalf("PSK metadata = %+v", h)
	}
	if fp.FingerprintModel != FingerprintModelVersion || fp.HandshakeType != HandshakeTypePSK || !fp.SessionResumption || fp.PSKIdentityCount != 1 || !fp.EarlyData {
		t.Fatalf("fingerprint session metadata = %+v", fp)
	}
	if bytes.Contains(fp.Normalized, []byte("ticket_age")) {
		t.Fatal("dynamic age in normalized")
	}
	bad := append([]byte(nil), psk...)
	binary.BigEndian.PutUint16(bad[:2], 0xffff)
	if _, err := Parse(fixture(extension(41, bad))); err == nil {
		t.Fatal("malformed PSK accepted")
	}
}

func TestResumedHandshakeVariantCanBeDeclared(t *testing.T) {
	raw := fixture(nil)
	h, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	h.HandshakeType = HandshakeTypeResumed
	fp, err := Calculate(h, raw, record(raw))
	if err != nil {
		t.Fatal(err)
	}
	if fp.HandshakeType != HandshakeTypeResumed || !fp.SessionResumption {
		t.Fatalf("resumed metadata = %+v", fp)
	}
}

func TestPostQuantumAndUnknownGroupsKeepNumericNames(t *testing.T) {
	supportedGroups := extension(10, vector16([]byte{0x11, 0xec, 0x12, 0x34}))
	keyShare := extension(51, vector16(append([]byte{0x11, 0xec}, vector16([]byte{1, 2, 3})...)))
	raw := fixture(append(supportedGroups, keyShare...))
	h, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(h.SupportedGroupNames) != 2 || h.SupportedGroupNames[0].NumericID != 4588 || h.SupportedGroupNames[0].ResolvedName != "x25519_mlkem768" || h.SupportedGroupNames[1].ResolvedName != "unknown" {
		t.Fatalf("supported group names = %+v", h.SupportedGroupNames)
	}
	for _, extension := range h.Extensions {
		if extension.ID != 51 {
			continue
		}
		shares, ok := extension.Fields["shares_named"].([]NumericIDName)
		if !ok || len(shares) != 1 || shares[0].NumericID != 4588 || shares[0].ResolvedName != "x25519_mlkem768" {
			t.Fatalf("key share names = %#v", extension.Fields["shares_named"])
		}
		return
	}
	t.Fatal("key_share extension not found")
}
