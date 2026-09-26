package quic

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"net/netip"
	"testing"
	"time"
)

func TestDerivePublishedInitialKeysV1AndV2(t *testing.T) {
	dcid, _ := hex.DecodeString("8394c8f03e515708")
	tests := []struct {
		version uint32
		key     string
		iv      string
		hp      string
	}{
		{Version1, "1f369613dd76d5467730efcbe3b1a22d", "fa044b2f42a3fd3b46fb255c", "9f50449e04a0e810283a1e9933adedd2"},
		{Version2, "8b1a0bc121284290a29e0971b5cd045d", "91f73e2351d8fa91660e909f", "45b95e15235d6f45a6b19cbcb0294ba9"},
	}
	for _, test := range tests {
		keys, err := deriveInitialKeys(test.version, dcid, true)
		if err != nil || hex.EncodeToString(keys.key) != test.key || hex.EncodeToString(keys.iv) != test.iv || hex.EncodeToString(keys.hp) != test.hp {
			t.Fatalf("version %#x keys = %x/%x/%x, error=%v", test.version, keys.key, keys.iv, keys.hp, err)
		}
	}
	keys, _ := deriveInitialKeys(Version1, dcid, true)
	hp, _ := aes.NewCipher(keys.hp)
	sample, _ := hex.DecodeString("d1b1c98dd7689fb8ec11d242b123dc9b")
	var mask [aes.BlockSize]byte
	hp.Encrypt(mask[:], sample)
	if hex.EncodeToString(mask[:5]) != "437b9aec36" {
		t.Fatalf("RFC 9001 header-protection mask = %x", mask[:5])
	}
}

func TestDecryptInitialAndRejectUnsupportedVariants(t *testing.T) {
	dcid := []byte{0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08}
	plaintext := append([]byte{1}, []byte("payload")...)
	packet := protectedInitial(Version1, dcid, []byte{1, 2, 3}, 9, plaintext)
	got, err := ParseInitialPacket(packet)
	if err != nil || got.Version != Version1 || got.PacketNumber != 9 || hex.EncodeToString(got.DCID) != hex.EncodeToString(dcid) || string(got.Plaintext) != string(plaintext) {
		t.Fatalf("decrypted Initial=%+v error=%v", got, err)
	}
	v2Packet := protectedInitial(Version2, dcid, []byte{1}, 10, plaintext)
	v2, err := ParseInitialPacket(v2Packet)
	if err != nil || v2.Version != Version2 || v2.PacketNumber != 10 || string(v2.Plaintext) != string(plaintext) {
		t.Fatalf("decrypted QUIC v2 Initial=%+v error=%v", v2, err)
	}
	unsupported := append([]byte(nil), packet...)
	binary.BigEndian.PutUint32(unsupported[1:5], 0xfaceb00c)
	if _, err := ParseInitialPacket(unsupported); !errors.Is(err, ErrUnsupportedVersion) {
		t.Fatalf("unsupported version error=%v", err)
	}
	notInitial := protectedInitial(Version1, dcid, []byte{1}, 0, plaintext)
	notInitial[0] = (notInitial[0] &^ 0x30) | 0x10
	if _, err := ParseInitialPacket(notInitial); !errors.Is(err, ErrNotInitial) {
		t.Fatalf("non-Initial packet type error=%v", err)
	}
}

func TestParseIPv6UDPPacket(t *testing.T) {
	payload := protectedInitial(Version2, []byte{1, 2, 3, 4}, []byte{5}, 0, make([]byte, 32))
	packet := make([]byte, 40+8+len(payload))
	packet[0] = 0x60
	binary.BigEndian.PutUint16(packet[4:6], uint16(8+len(payload)))
	packet[6], packet[7] = 17, 64
	copy(packet[8:24], netip.MustParseAddr("2001:db8::10").AsSlice())
	copy(packet[24:40], netip.MustParseAddr("2001:db8::20").AsSlice())
	binary.BigEndian.PutUint16(packet[40:42], 53000)
	binary.BigEndian.PutUint16(packet[42:44], 443)
	binary.BigEndian.PutUint16(packet[44:46], uint16(8+len(payload)))
	copy(packet[48:], payload)
	got, err := ParseUDPPacket(packet)
	if err != nil || got.Source != "[2001:db8::10]:53000" || got.Destination != "[2001:db8::20]:443" || string(got.Payload) != string(payload) {
		t.Fatalf("IPv6 UDP parse=%+v error=%v", got, err)
	}
}

func TestParseCryptoFramesAndRejectsUnsupportedFrame(t *testing.T) {
	data := []byte{0x06, 0x02, 0x03, 1, 2, 3, 0x00, 0x01} // CRYPTO + padding + PING
	frames, err := ParseCryptoFrames(data)
	if err != nil || len(frames) != 1 || frames[0].Offset != 2 || string(frames[0].Data) != string([]byte{1, 2, 3}) {
		t.Fatalf("CRYPTO frames=%+v error=%v", frames, err)
	}
	if _, err := ParseCryptoFrames([]byte{0x1e}); !errors.Is(err, ErrUnsupportedFrame) {
		t.Fatalf("unsupported frame error=%v", err)
	}
}

func TestSensorReassemblesClientHelloAndParsesTransportParameters(t *testing.T) {
	hello := testClientHello()
	dcid := []byte{0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08}
	crypto := appendVarint(nil, 6)
	crypto = appendVarint(crypto, uint64(len(hello)/2))
	crypto = appendVarint(crypto, uint64(len(hello)-len(hello)/2))
	crypto = append(crypto, hello[len(hello)/2:]...)
	first := makeIPv4UDP(paddedInitial(Version1, dcid, []byte{9, 8}, 1, crypto))
	crypto = appendVarint(nil, 6)
	crypto = appendVarint(crypto, 0)
	crypto = appendVarint(crypto, uint64(len(hello)/2))
	crypto = append(crypto, hello[:len(hello)/2]...)
	second := makeIPv4UDP(paddedInitial(Version1, dcid, []byte{9, 8}, 2, crypto))
	sensor := NewSensor(Config{})
	at := time.Date(2026, 9, 25, 15, 0, 0, 0, time.UTC)
	if got, err := sensor.ObserveIP(first, at); err != nil || got != nil {
		t.Fatalf("first out-of-order Initial=%+v error=%v", got, err)
	}
	got, err := sensor.ObserveIP(second, at.Add(time.Millisecond))
	if err != nil || got == nil {
		t.Fatalf("completed QUIC observation=%+v error=%v", got, err)
	}
	if got.Version != Version1 || got.ClientIP != "192.0.2.10" || got.Hello.ServerName != "quic.test" || len(got.TransportParameters) != 2 {
		t.Fatalf("QUIC observation fields=%+v", got)
	}
	if got.TransportParameters[0].Name != "max_idle_timeout" || got.TransportParameters[0].Value == nil || *got.TransportParameters[0].Value != 30 || got.TransportParameters[1].Name != "initial_source_connection_id" || got.TransportParameters[1].Kind != "opaque" || got.TransportParameters[1].Length != 2 || got.TransportParameters[1].Value != nil {
		t.Fatalf("transport parameters were not safely normalized: %+v", got.TransportParameters)
	}
}

func paddedInitial(version uint32, dcid, scid []byte, packetNumber uint64, plaintext []byte) []byte {
	for {
		packet := protectedInitial(version, dcid, scid, packetNumber, plaintext)
		if len(packet) >= 1200 {
			return packet
		}
		plaintext = append(plaintext, make([]byte, 1200-len(packet))...)
	}
}

func TestSensorDoesNotClaimAuthenticationFailureAsRecognized(t *testing.T) {
	dcid := []byte{1, 2, 3, 4}
	packet := paddedInitial(Version1, dcid, []byte{1}, 0, []byte{0x06, 0, 1, 1})
	packet[len(packet)-1] ^= 1
	if _, err := ParseInitialPacket(packet); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("tampered Initial error=%v", err)
	}
	if observation, err := NewSensor(Config{}).ObserveIP(makeIPv4UDP(packet), time.Now().UTC()); !errors.Is(err, ErrAuthentication) || observation != nil {
		t.Fatalf("tampered packet sensor result=%+v error=%v", observation, err)
	}
}

func TestSensorRecognizesQUICv2AndRejectsShortInitialDatagrams(t *testing.T) {
	dcid := []byte{0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08}
	crypto := appendVarint(nil, 6)
	crypto = appendVarint(crypto, 0)
	hello := testClientHello()
	crypto = appendVarint(crypto, uint64(len(hello)))
	crypto = append(crypto, hello...)
	sensor := NewSensor(Config{})
	at := time.Date(2026, 9, 25, 15, 30, 0, 0, time.UTC)
	got, err := sensor.ObserveIP(makeIPv4UDP(paddedInitial(Version2, dcid, []byte{1}, 0, crypto)), at)
	if err != nil || got == nil || got.Version != Version2 || got.Hello.ServerName != "quic.test" {
		t.Fatalf("QUIC v2 sensor observation=%+v error=%v", got, err)
	}
	if _, err := sensor.ObserveIP(makeIPv4UDP(protectedInitial(Version1, dcid, []byte{1}, 0, crypto)), at); !errors.Is(err, ErrMalformedPacket) {
		t.Fatalf("undersized Initial datagram error=%v", err)
	}
}

func TestSensorProcessesCoalescedInitialsAndReconstructsPacketNumber(t *testing.T) {
	hello := testClientHello()
	dcid := []byte{0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08}
	firstFrame := appendVarint(nil, 6)
	firstFrame = appendVarint(firstFrame, 0)
	firstFrame = appendVarint(firstFrame, uint64(len(hello)/2))
	firstFrame = append(firstFrame, hello[:len(hello)/2]...)
	secondFrame := appendVarint(nil, 6)
	secondFrame = appendVarint(secondFrame, uint64(len(hello)/2))
	secondFrame = appendVarint(secondFrame, uint64(len(hello)-len(hello)/2))
	secondFrame = append(secondFrame, hello[len(hello)/2:]...)
	first := protectedInitial(Version1, dcid, nil, 255, firstFrame)
	second := protectedInitial(Version1, dcid, nil, 256, secondFrame)
	if _, err := ParseInitialPacket(second); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("truncated packet number without history error=%v", err)
	}
	largest := uint64(255)
	decoded, err := parseInitialPacket(second, &largest)
	if err != nil || decoded.PacketNumber != 256 {
		t.Fatalf("reconstructed packet number=%d error=%v", decoded.PacketNumber, err)
	}
	for len(first)+len(second) < 1200 {
		secondFrame = append(secondFrame, make([]byte, 1200-len(first)-len(second))...)
		second = protectedInitial(Version1, dcid, nil, 256, secondFrame)
	}
	datagram := append(append([]byte(nil), first...), second...)
	got, err := NewSensor(Config{}).ObserveIP(makeIPv4UDP(datagram), time.Now().UTC())
	if err != nil || got == nil || got.PacketNumber != 256 || got.Hello.ServerName != "quic.test" {
		t.Fatalf("coalesced Initial observation=%+v error=%v", got, err)
	}
}

func TestSensorContinuesAfterInvalidCoalescedInitial(t *testing.T) {
	dcid := []byte{1, 2, 3, 4}
	bad := protectedInitial(Version1, dcid, nil, 0, make([]byte, 32))
	bad[len(bad)-1] ^= 1
	hello := testClientHello()
	crypto := appendVarint(nil, 6)
	crypto = appendVarint(crypto, 0)
	crypto = appendVarint(crypto, uint64(len(hello)))
	crypto = append(crypto, hello...)
	good := protectedInitial(Version1, dcid, nil, 1, crypto)
	for len(bad)+len(good) < 1200 {
		crypto = append(crypto, make([]byte, 1200-len(bad)-len(good))...)
		good = protectedInitial(Version1, dcid, nil, 1, crypto)
	}
	datagram := append(append([]byte(nil), bad...), good...)
	got, err := NewSensor(Config{}).ObserveIP(makeIPv4UDP(datagram), time.Now().UTC())
	if err != nil || got == nil || got.PacketNumber != 1 {
		t.Fatalf("valid Initial after unauthenticated packet=%+v error=%v", got, err)
	}
}

func protectedInitial(version uint32, dcid, scid []byte, packetNumber uint64, plaintext []byte) []byte {
	typ := byte(0)
	labelsVersion := version
	if version == Version2 {
		typ = 1
	} else {
		labelsVersion = Version1
	}
	first := byte(0xc0 | typ<<4) // long header, fixed bit, Initial, 1-byte PN
	header := []byte{first, byte(version >> 24), byte(version >> 16), byte(version >> 8), byte(version), byte(len(dcid))}
	header = append(header, dcid...)
	header = append(header, byte(len(scid)))
	header = append(header, scid...)
	header = appendVarint(header, 0) // token length
	length := 1 + len(plaintext) + 16
	header = appendVarint(header, uint64(length))
	pnOffset := len(header)
	header = append(header, byte(packetNumber))
	keys, _ := deriveInitialKeys(labelsVersion, dcid, true)
	block, _ := aes.NewCipher(keys.key)
	aead, _ := cipher.NewGCM(block)
	nonce := append([]byte(nil), keys.iv...)
	for i := 0; i < 8; i++ {
		nonce[len(nonce)-1-i] ^= byte(packetNumber >> (8 * i))
	}
	ciphertext := aead.Seal(nil, nonce, plaintext, header)
	packet := append(append([]byte(nil), header...), ciphertext...)
	hp, _ := aes.NewCipher(keys.hp)
	var mask [aes.BlockSize]byte
	hp.Encrypt(mask[:], packet[pnOffset+4:pnOffset+4+aes.BlockSize])
	packet[0] ^= mask[0] & 0x0f
	packet[pnOffset] ^= mask[1]
	return packet
}

func testClientHello() []byte {
	body := []byte{0x03, 0x03}
	body = append(body, make([]byte, 32)...)
	body = append(body, 0, 0, 2, 0xc0, 0x2f, 1, 0)
	domain := []byte("quic.test")
	name := []byte{0, byte(len(domain) + 3), 0, byte(len(domain) >> 8), byte(len(domain))}
	name = append(name, domain...)
	parameters := appendVarint(nil, 1)
	parameters = appendVarint(parameters, 1)
	parameters = append(parameters, 30)
	parameters = appendVarint(parameters, 0x0f)
	parameters = appendVarint(parameters, 2)
	parameters = append(parameters, 0xaa, 0xbb)
	extensions := append([]byte{}, 0, 0, byte(len(name)>>8), byte(len(name)))
	extensions = append(extensions, name...)
	extensions = append(extensions, 0, 57, byte(len(parameters)>>8), byte(len(parameters)))
	extensions = append(extensions, parameters...)
	body = append(body, byte(len(extensions)>>8), byte(len(extensions)))
	body = append(body, extensions...)
	handshake := []byte{1, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}
	return append(handshake, body...)
}

func makeIPv4UDP(payload []byte) []byte {
	packet := make([]byte, 20+8+len(payload))
	packet[0] = 0x45
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	packet[8], packet[9] = 64, 17
	copy(packet[12:16], []byte{192, 0, 2, 10})
	copy(packet[16:20], []byte{192, 0, 2, 53})
	binary.BigEndian.PutUint16(packet[20:22], 53000)
	binary.BigEndian.PutUint16(packet[22:24], 443)
	binary.BigEndian.PutUint16(packet[24:26], uint16(8+len(payload)))
	copy(packet[28:], payload)
	return packet
}
