package tlshello

import (
	"crypto/md5" // JA3S mandates MD5; this value is not used for authentication.
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

const (
	ServerHelloType       = 2
	HelloRetryRequestType = "HELLO_RETRY_REQUEST"
	JA3SVersion           = "JA3S/1"
	JA4SVersion           = "FoxIO-JA4S-TCP/2026-09-24"
)

var ErrMalformedServerHello = errors.New("malformed_server_hello")

type ServerExtension struct {
	ID       uint16 `json:"id"`
	Position int    `json:"position"`
	Length   int    `json:"length"`
}

type ServerField[T any] struct {
	Value     T      `json:"value"`
	Source    string `json:"source"`
	Available bool   `json:"available"`
	Reason    string `json:"reason,omitempty"`
}

type ServerHelloFields struct {
	LegacyVersion       ServerField[uint16]            `json:"legacy_version"`
	TLSVersion          ServerField[uint16]            `json:"tls_version"`
	SelectedCipher      ServerField[uint16]            `json:"selected_cipher"`
	CompressionMethod   ServerField[byte]              `json:"compression_method"`
	Extensions          ServerField[[]ServerExtension] `json:"extensions"`
	EncryptedExtensions ServerField[[]ServerExtension] `json:"encrypted_extensions"`
	SelectedALPN        ServerField[string]            `json:"selected_alpn"`
	SelectedGroup       ServerField[uint16]            `json:"selected_group"`
	SessionResumption   ServerField[bool]              `json:"session_resumption"`
	HelloRetryRequest   ServerField[bool]              `json:"hello_retry_request"`
	SessionIDLength     ServerField[int]               `json:"session_id_length"`
	HandshakeLength     ServerField[int]               `json:"handshake_length"`
}

type ServerHello struct {
	Fields ServerHelloFields `json:"fields"`
}

type ServerFingerprints struct {
	JA3S        string `json:"ja3s"`
	JA3SHash    string `json:"ja3s_hash"`
	JA3SVersion string `json:"ja3s_version"`
	JA4S        string `json:"ja4s"`
	JA4SVersion string `json:"ja4s_version"`
}

var helloRetryRequestRandom = [32]byte{
	0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11,
	0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91,
	0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e,
	0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c,
}

// ParseServerHello parses one TLS Handshake message, including its 4-byte
// handshake header. Record headers are intentionally not accepted here.
func ParseServerHello(raw []byte) (ServerHello, error) {
	if len(raw) < 4 || raw[0] != ServerHelloType {
		return ServerHello{}, ErrMalformedServerHello
	}
	length := int(raw[1])<<16 | int(raw[2])<<8 | int(raw[3])
	if length != len(raw)-4 || length < 38 || length > MaxHelloSize {
		return ServerHello{}, fmt.Errorf("%w: invalid handshake length", ErrMalformedServerHello)
	}
	body := raw[4:]
	legacyVersion := binary.BigEndian.Uint16(body[:2])
	serverRandom := body[2:34]
	position := 34
	if position >= len(body) {
		return ServerHello{}, ErrMalformedServerHello
	}
	sessionIDLength := int(body[position])
	position++
	if sessionIDLength > 32 || position+sessionIDLength+3 > len(body) {
		return ServerHello{}, ErrMalformedServerHello
	}
	position += sessionIDLength
	cipherSuite := binary.BigEndian.Uint16(body[position : position+2])
	position += 2
	compressionMethod := body[position]
	position++

	serverHello := ServerHello{
		Fields: ServerHelloFields{
			LegacyVersion:       availableServerField(legacyVersion),
			TLSVersion:          availableServerField(legacyVersion),
			SelectedCipher:      availableServerField(cipherSuite),
			CompressionMethod:   availableServerField(compressionMethod),
			Extensions:          availableServerField([]ServerExtension{}),
			EncryptedExtensions: unavailableServerField[[]ServerExtension]("not_applicable"),
			SelectedALPN:        unavailableServerField[string]("not_present"),
			SelectedGroup:       unavailableServerField[uint16]("not_present"),
			SessionResumption:   unavailableServerField[bool]("requires_client_hello"),
			HelloRetryRequest:   availableServerField(equalRandom(serverRandom, helloRetryRequestRandom[:])),
			SessionIDLength:     availableServerField(sessionIDLength),
			HandshakeLength:     availableServerField(length),
		},
	}
	if position == len(body) {
		return serverHello, nil
	}
	if position+2 > len(body) {
		return ServerHello{}, ErrMalformedServerHello
	}
	extensionsLength := int(binary.BigEndian.Uint16(body[position : position+2]))
	position += 2
	if extensionsLength != len(body)-position {
		return ServerHello{}, fmt.Errorf("%w: invalid extensions length", ErrMalformedServerHello)
	}
	extensions := body[position:]
	selectedPSK := false
	for index := 0; len(extensions) > 0; index++ {
		if len(extensions) < 4 {
			return ServerHello{}, ErrMalformedServerHello
		}
		id := binary.BigEndian.Uint16(extensions[:2])
		extensionLength := int(binary.BigEndian.Uint16(extensions[2:4]))
		if extensionLength > len(extensions)-4 {
			return ServerHello{}, ErrMalformedServerHello
		}
		value := extensions[4 : 4+extensionLength]
		serverHello.Fields.Extensions.Value = append(serverHello.Fields.Extensions.Value, ServerExtension{ID: id, Position: index, Length: extensionLength})
		switch id {
		case 43: // supported_versions
			if len(value) != 2 {
				return ServerHello{}, fmt.Errorf("%w: invalid supported_versions", ErrMalformedServerHello)
			}
			serverHello.Fields.TLSVersion = availableServerField(binary.BigEndian.Uint16(value))
		case 16: // application_layer_protocol_negotiation
			if len(value) < 3 || int(binary.BigEndian.Uint16(value[:2])) != len(value)-2 {
				return ServerHello{}, fmt.Errorf("%w: invalid ALPN", ErrMalformedServerHello)
			}
			protocolLength := int(value[2])
			if protocolLength == 0 || 3+protocolLength != len(value) {
				return ServerHello{}, fmt.Errorf("%w: invalid selected ALPN", ErrMalformedServerHello)
			}
			serverHello.Fields.SelectedALPN = availableServerField(string(value[3:]))
		case 51: // key_share
			if serverHello.Fields.HelloRetryRequest.Value {
				if len(value) != 2 {
					return ServerHello{}, fmt.Errorf("%w: invalid hello retry key_share", ErrMalformedServerHello)
				}
			} else if len(value) < 4 || int(binary.BigEndian.Uint16(value[2:4])) != len(value)-4 || len(value) == 4 {
				return ServerHello{}, fmt.Errorf("%w: invalid server key_share", ErrMalformedServerHello)
			}
			serverHello.Fields.SelectedGroup = availableServerField(binary.BigEndian.Uint16(value[:2]))
		case 41: // pre_shared_key
			if len(value) != 2 {
				return ServerHello{}, fmt.Errorf("%w: invalid pre_shared_key", ErrMalformedServerHello)
			}
			selectedPSK = true
		}
		extensions = extensions[4+extensionLength:]
	}
	if serverHello.Fields.TLSVersion.Value == 0x0304 {
		switch {
		case serverHello.Fields.HelloRetryRequest.Value:
			serverHello.Fields.SessionResumption = unavailableServerField[bool]("hello_retry_request")
		case selectedPSK:
			serverHello.Fields.SessionResumption = unavailableServerField[bool]("psk_selected_type_unknown")
		default:
			serverHello.Fields.SessionResumption = availableServerField(false)
		}
		serverHello.Fields.EncryptedExtensions.Reason = "encrypted_without_keys"
		if !serverHello.Fields.SelectedALPN.Available {
			serverHello.Fields.SelectedALPN.Reason = "encrypted_without_keys"
		}
	}
	return serverHello, nil
}

func CalculateServerFingerprints(hello *ServerHello) (ServerFingerprints, error) {
	if hello == nil {
		return ServerFingerprints{}, ErrMalformedServerHello
	}
	ids := make([]string, len(hello.Fields.Extensions.Value))
	for index, extension := range hello.Fields.Extensions.Value {
		if IsGREASE(extension.ID) {
			continue
		}
		ids[index] = strconv.Itoa(int(extension.ID))
	}
	cleanIDs := make([]string, 0, len(ids))
	for _, id := range ids {
		if id != "" {
			cleanIDs = append(cleanIDs, id)
		}
	}
	ja3s := fmt.Sprintf("%d,%d,%s", hello.Fields.TLSVersion.Value, hello.Fields.SelectedCipher.Value, strings.Join(cleanIDs, "-"))
	digest := md5.Sum([]byte(ja3s))
	ja4s := calculateJA4S(hello)
	return ServerFingerprints{
		JA3S: ja3s, JA3SHash: hex.EncodeToString(digest[:]), JA3SVersion: JA3SVersion,
		JA4S: ja4s, JA4SVersion: JA4SVersion,
	}, nil
}

func calculateJA4S(hello *ServerHello) string {
	version := serverVersionCode(hello.Fields.TLSVersion.Value)
	extensions := hello.Fields.Extensions.Value
	extensionIDs := make([]string, len(extensions))
	for index, extension := range extensions {
		extensionIDs[index] = fmt.Sprintf("%04x", extension.ID)
	}
	extensionHash := "000000000000"
	if len(extensionIDs) > 0 {
		digest := sha256.Sum256([]byte(strings.Join(extensionIDs, ",")))
		extensionHash = hex.EncodeToString(digest[:])[:12]
	}
	alpn := "00"
	if hello.Fields.SelectedALPN.Available {
		value := []byte(hello.Fields.SelectedALPN.Value)
		if len(value) > 0 {
			first, last := value[0], value[len(value)-1]
			if !isJA4SASCII(first) {
				first = '9'
			}
			if !isJA4SASCII(last) {
				last = '9'
			}
			alpn = string([]byte{first, last})
		}
	}
	return fmt.Sprintf("t%s%02d%s_%04x_%s", version, min(99, len(extensions)), alpn, hello.Fields.SelectedCipher.Value, extensionHash)
}

func serverVersionCode(version uint16) string {
	if code, ok := map[uint16]string{0x0002: "s2", 0x0300: "s3", 0x0301: "10", 0x0302: "11", 0x0303: "12", 0x0304: "13"}[version]; ok {
		return code
	}
	return "00"
}

func isJA4SASCII(value byte) bool {
	return value < 0x80
}

func availableServerField[T any](value T) ServerField[T] {
	return ServerField[T]{Value: value, Source: "wire_server_hello", Available: true}
}

func unavailableServerField[T any](reason string) ServerField[T] {
	return ServerField[T]{Source: "wire_server_hello", Available: false, Reason: reason}
}

func equalRandom(left, right []byte) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}
