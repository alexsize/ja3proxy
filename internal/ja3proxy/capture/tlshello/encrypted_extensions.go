package tlshello

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"net"
	"os"
	"strings"
	"sync"

	"golang.org/x/crypto/chacha20poly1305"
)

const (
	EncryptedExtensionsType    = 8
	EncryptedExtensionsVersion = "TLS13-EE/1"
	maxTLS13CiphertextRecord   = 16640
	maxHandshakeBuffer         = MaxHelloSize
)

var ErrMalformedEncryptedExtensions = errors.New("malformed_encrypted_extensions")

type EncryptedExtensions struct {
	Extensions   ServerField[[]ServerExtension] `json:"extensions"`
	SelectedALPN ServerField[string]            `json:"selected_alpn"`
}

type EncryptedExtensionsCapture struct {
	Status     string              `json:"completeness"`
	Reason     string              `json:"reason,omitempty"`
	Extensions EncryptedExtensions `json:"encrypted_extensions"`
}

func ParseEncryptedExtensions(raw []byte) (EncryptedExtensions, error) {
	if len(raw) < 6 || len(raw) > maxHandshakeBuffer || raw[0] != EncryptedExtensionsType {
		return EncryptedExtensions{}, ErrMalformedEncryptedExtensions
	}
	bodyLength := int(raw[1])<<16 | int(raw[2])<<8 | int(raw[3])
	if bodyLength != len(raw)-4 || bodyLength < 2 {
		return EncryptedExtensions{}, ErrMalformedEncryptedExtensions
	}
	vectorLength := int(binary.BigEndian.Uint16(raw[4:6]))
	if vectorLength != len(raw)-6 {
		return EncryptedExtensions{}, ErrMalformedEncryptedExtensions
	}
	result := EncryptedExtensions{
		Extensions:   ServerField[[]ServerExtension]{Value: []ServerExtension{}, Source: "decrypted_encrypted_extensions", Available: true},
		SelectedALPN: ServerField[string]{Source: "decrypted_encrypted_extensions", Available: false, Reason: "not_present"},
	}
	extensions := raw[6:]
	seen := make(map[uint16]struct{})
	for position := 0; len(extensions) > 0; position++ {
		if len(extensions) < 4 {
			return EncryptedExtensions{}, ErrMalformedEncryptedExtensions
		}
		id := binary.BigEndian.Uint16(extensions[:2])
		if _, duplicate := seen[id]; duplicate {
			return EncryptedExtensions{}, ErrMalformedEncryptedExtensions
		}
		seen[id] = struct{}{}
		length := int(binary.BigEndian.Uint16(extensions[2:4]))
		if length > len(extensions)-4 {
			return EncryptedExtensions{}, ErrMalformedEncryptedExtensions
		}
		value := extensions[4 : 4+length]
		result.Extensions.Value = append(result.Extensions.Value, ServerExtension{ID: id, Position: position, Length: length})
		if id == 16 {
			if len(value) < 4 || int(binary.BigEndian.Uint16(value[:2])) != len(value)-2 {
				return EncryptedExtensions{}, ErrMalformedEncryptedExtensions
			}
			protocolLength := int(value[2])
			if protocolLength == 0 || protocolLength+3 != len(value) {
				return EncryptedExtensions{}, ErrMalformedEncryptedExtensions
			}
			result.SelectedALPN = ServerField[string]{Value: string(value[3:]), Source: "decrypted_encrypted_extensions", Available: true}
		}
		extensions = extensions[4+length:]
	}
	return result, nil
}

// LoadServerHandshakeTrafficSecret reads NSS key-log format and returns only
// the matching server handshake traffic secret. The caller owns and must clear
// the returned key material after use.
func LoadServerHandshakeTrafficSecret(path string, clientRandom []byte) ([]byte, error) {
	if path == "" || len(clientRandom) != 32 {
		return nil, os.ErrNotExist
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, errors.New("TLS key-log file unavailable")
	}
	defer file.Close()
	wanted := hex.EncodeToString(clientRandom)
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 4096), 1<<20)
	var selected []byte
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) != 3 || fields[0] != "SERVER_HANDSHAKE_TRAFFIC_SECRET" || !strings.EqualFold(fields[1], wanted) {
			continue
		}
		secret, decodeErr := hex.DecodeString(fields[2])
		if decodeErr != nil || len(secret) == 0 {
			clear(selected)
			return nil, errors.New("TLS key-log secret is malformed")
		}
		clear(selected)
		selected = secret
	}
	if err := scanner.Err(); err != nil {
		clear(selected)
		return nil, errors.New("TLS key-log file could not be read")
	}
	if len(selected) == 0 {
		return nil, os.ErrNotExist
	}
	return selected, nil
}

type EncryptedExtensionsConn struct {
	net.Conn
	mu           sync.Mutex
	keyLogPath   string
	clientRandom func() []byte
	publish      func(EncryptedExtensionsCapture)
	wire         []byte
	handshake    []byte
	secret       []byte
	key          []byte
	iv           []byte
	cipherSuite  uint16
	sequence     uint64
	deferred     [][]byte
	helloSeen    bool
	finished     bool
}

func WrapEncryptedExtensions(conn net.Conn, keyLogPath string, clientRandom func() []byte, publish func(EncryptedExtensionsCapture)) *EncryptedExtensionsConn {
	return &EncryptedExtensionsConn{Conn: conn, keyLogPath: keyLogPath, clientRandom: clientRandom, publish: publish}
}

func (c *EncryptedExtensionsConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	c.mu.Lock()
	if n > 0 && !c.finished {
		c.feed(p[:n])
	}
	if err != nil && !c.finished && c.helloSeen {
		reason := "truncated"
		if len(c.secret) == 0 {
			reason = "session_secret_unavailable"
		}
		c.emitUnavailable(reason)
	}
	c.mu.Unlock()
	return n, err
}

func (c *EncryptedExtensionsConn) Close() error {
	c.mu.Lock()
	if !c.finished && c.helloSeen {
		reason := "truncated"
		if len(c.secret) == 0 {
			reason = "session_secret_unavailable"
		}
		c.emitUnavailable(reason)
	}
	c.clearSecrets()
	c.mu.Unlock()
	return c.Conn.Close()
}

func (c *EncryptedExtensionsConn) feed(p []byte) {
	if len(c.wire)+len(p) > 1<<20 {
		c.emitUnavailable("record_buffer_limit")
		return
	}
	c.wire = append(c.wire, p...)
	for len(c.wire) >= 5 && !c.finished {
		recordLength := int(binary.BigEndian.Uint16(c.wire[3:5]))
		if recordLength > maxTLS13CiphertextRecord {
			c.emitUnavailable("record_limit")
			return
		}
		if len(c.wire) < 5+recordLength {
			return
		}
		record := append([]byte(nil), c.wire[:5+recordLength]...)
		c.wire = c.wire[5+recordLength:]
		c.processRecord(record)
	}
}

func (c *EncryptedExtensionsConn) processRecord(record []byte) {
	switch record[0] {
	case 20: // TLS 1.3 compatibility ChangeCipherSpec is not encrypted.
		return
	case 22:
		if c.helloSeen {
			return
		}
		c.handshake = append(c.handshake, record[5:]...)
		if len(c.handshake) > maxHandshakeBuffer {
			c.emitUnavailable("handshake_buffer_limit")
			return
		}
		for len(c.handshake) >= 4 {
			messageLength := int(c.handshake[1])<<16 | int(c.handshake[2])<<8 | int(c.handshake[3])
			if messageLength+4 > maxHandshakeBuffer {
				c.emitUnavailable("handshake_message_limit")
				return
			}
			if len(c.handshake) < messageLength+4 {
				return
			}
			message := append([]byte(nil), c.handshake[:messageLength+4]...)
			c.handshake = c.handshake[messageLength+4:]
			if message[0] != ServerHelloType {
				continue
			}
			serverHello, err := ParseServerHello(message)
			if err != nil {
				c.emitUnavailable("malformed_server_hello")
				return
			}
			if serverHello.Fields.HelloRetryRequest.Value {
				continue
			}
			if serverHello.Fields.TLSVersion.Value != 0x0304 {
				c.finished = true
				return
			}
			c.helloSeen = true
			c.cipherSuite = serverHello.Fields.SelectedCipher.Value
			return
		}
	case 23:
		if !c.helloSeen {
			return
		}
		if len(c.secret) == 0 {
			if err := c.loadSecret(); err != nil {
				if len(c.deferred) >= 64 || deferredBytes(c.deferred)+len(record) > 1<<20 {
					c.emitUnavailable("deferred_record_limit")
					return
				}
				c.deferred = append(c.deferred, append([]byte(nil), record...))
				return
			}
			deferred := c.deferred
			c.deferred = nil
			for _, pending := range deferred {
				c.processEncryptedRecord(pending)
				clear(pending)
				if c.finished {
					return
				}
			}
		}
		c.processEncryptedRecord(record)
	}
}

func (c *EncryptedExtensionsConn) processEncryptedRecord(record []byte) {
	plaintext, err := decryptTLS13Record(record, c.key, c.iv, c.sequence, c.cipherSuite)
	c.sequence++
	if err != nil {
		c.emitUnavailable("decryption_failed")
		return
	}
	contentEnd := len(plaintext)
	for contentEnd > 0 && plaintext[contentEnd-1] == 0 {
		contentEnd--
	}
	if contentEnd == 0 || plaintext[contentEnd-1] != 22 {
		c.emitUnavailable("unexpected_encrypted_content")
		return
	}
	c.handshake = append(c.handshake, plaintext[:contentEnd-1]...)
	clear(plaintext)
	if len(c.handshake) > maxHandshakeBuffer {
		c.emitUnavailable("handshake_buffer_limit")
		return
	}
	if len(c.handshake) < 4 {
		return
	}
	messageLength := int(c.handshake[1])<<16 | int(c.handshake[2])<<8 | int(c.handshake[3])
	if c.handshake[0] != EncryptedExtensionsType || messageLength+4 > maxHandshakeBuffer {
		c.emitUnavailable("unexpected_handshake_message")
		return
	}
	if len(c.handshake) < messageLength+4 {
		return
	}
	parsed, err := ParseEncryptedExtensions(c.handshake[:messageLength+4])
	if err != nil {
		c.emitUnavailable("malformed_encrypted_extensions")
		return
	}
	c.finished = true
	c.publishCapture(EncryptedExtensionsCapture{Status: "complete", Extensions: parsed})
	c.clearSecrets()
}

func (c *EncryptedExtensionsConn) loadSecret() error {
	if c.clientRandom == nil {
		return fmt.Errorf("client random unavailable")
	}
	secret, err := LoadServerHandshakeTrafficSecret(c.keyLogPath, c.clientRandom())
	if err != nil {
		return err
	}
	key, iv, err := deriveTLS13KeyIV(secret, c.cipherSuite)
	if err != nil {
		clear(secret)
		return err
	}
	c.secret, c.key, c.iv = secret, key, iv
	return nil
}

func deferredBytes(records [][]byte) int {
	total := 0
	for _, record := range records {
		total += len(record)
	}
	return total
}

func (c *EncryptedExtensionsConn) emitUnavailable(reason string) {
	if c.finished {
		return
	}
	c.finished = true
	c.publishCapture(EncryptedExtensionsCapture{
		Status: "partial", Reason: reason,
		Extensions: EncryptedExtensions{
			Extensions:   ServerField[[]ServerExtension]{Source: "decrypted_encrypted_extensions", Available: false, Reason: reason},
			SelectedALPN: ServerField[string]{Source: "decrypted_encrypted_extensions", Available: false, Reason: reason},
		},
	})
	c.clearSecrets()
}

func (c *EncryptedExtensionsConn) publishCapture(capture EncryptedExtensionsCapture) {
	if c.publish != nil {
		c.publish(capture)
	}
}

func (c *EncryptedExtensionsConn) clearSecrets() {
	clear(c.secret)
	clear(c.key)
	clear(c.iv)
	c.secret, c.key, c.iv = nil, nil, nil
	clear(c.handshake)
	c.handshake = nil
	clear(c.wire)
	c.wire = nil
	for _, record := range c.deferred {
		clear(record)
	}
	c.deferred = nil
}

func decryptTLS13Record(record, key, iv []byte, sequence uint64, suite uint16) ([]byte, error) {
	var aead cipher.AEAD
	var err error
	switch suite {
	case 0x1301:
		var block cipher.Block
		block, err = aes.NewCipher(key)
		if err == nil {
			aead, err = cipher.NewGCM(block)
		}
	case 0x1302:
		var block cipher.Block
		block, err = aes.NewCipher(key)
		if err == nil {
			aead, err = cipher.NewGCM(block)
		}
	case 0x1303:
		aead, err = chacha20poly1305.New(key)
	default:
		return nil, errors.New("unsupported TLS 1.3 cipher suite")
	}
	if err != nil || len(iv) != aead.NonceSize() {
		return nil, errors.New("invalid TLS 1.3 traffic key")
	}
	nonce := append([]byte(nil), iv...)
	for index := 0; index < 8; index++ {
		nonce[len(nonce)-1-index] ^= byte(sequence >> (8 * index))
	}
	return aead.Open(nil, nonce, record[5:], record[:5])
}

func deriveTLS13KeyIV(secret []byte, suite uint16) ([]byte, []byte, error) {
	hashFunc, keyLength := func() (func() hash.Hash, int) {
		switch suite {
		case 0x1301:
			return sha256.New, 16
		case 0x1302:
			return sha512.New384, 32
		case 0x1303:
			return sha256.New, chacha20poly1305.KeySize
		default:
			return nil, 0
		}
	}()
	if hashFunc == nil || len(secret) != hashFunc().Size() {
		return nil, nil, errors.New("unsupported TLS 1.3 traffic secret")
	}
	return tls13ExpandLabel(hashFunc, secret, "key", keyLength), tls13ExpandLabel(hashFunc, secret, "iv", 12), nil
}

func tls13ExpandLabel(hashFunc func() hash.Hash, secret []byte, label string, length int) []byte {
	fullLabel := []byte("tls13 " + label)
	info := make([]byte, 2, 4+len(fullLabel))
	binary.BigEndian.PutUint16(info, uint16(length))
	info = append(info, byte(len(fullLabel)))
	info = append(info, fullLabel...)
	info = append(info, 0)
	var output, previous []byte
	for counter := byte(1); len(output) < length; counter++ {
		mac := hmac.New(hashFunc, secret)
		_, _ = mac.Write(previous)
		_, _ = mac.Write(info)
		_, _ = mac.Write([]byte{counter})
		previous = mac.Sum(nil)
		output = append(output, previous...)
	}
	return output[:length]
}
