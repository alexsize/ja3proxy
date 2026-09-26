//go:build windows

package pcap

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"syscall"
	"time"
	"unsafe"
)

const (
	pcapTimeoutMillis = 200
)

var (
	pcapDLL         = syscall.NewLazyDLL("wpcap.dll")
	findAllDevsProc = pcapDLL.NewProc("pcap_findalldevs")
	freeAllDevsProc = pcapDLL.NewProc("pcap_freealldevs")
	openLiveProc    = pcapDLL.NewProc("pcap_open_live")
	nextExProc      = pcapDLL.NewProc("pcap_next_ex")
	datalinkProc    = pcapDLL.NewProc("pcap_datalink")
	closeProc       = pcapDLL.NewProc("pcap_close")
)

type deviceNode struct {
	next        *deviceNode
	name        *byte
	description *byte
	addresses   unsafe.Pointer
	flags       uint32
}

type packetHeader struct {
	seconds      int32
	microseconds int32
	capturedLen  uint32
	originalLen  uint32
}

type liveSource struct {
	handle   uintptr
	linkType int
}

func ListDevices() ([]Device, error) {
	if err := pcapDLL.Load(); err != nil {
		return nil, fmt.Errorf("load Npcap wpcap.dll: %w", err)
	}
	var head *deviceNode
	errbuf := make([]byte, 256)
	result, _, _ := findAllDevsProc.Call(uintptr(unsafe.Pointer(&head)), uintptr(unsafe.Pointer(&errbuf[0])))
	if int32(result) != 0 {
		return nil, fmt.Errorf("pcap_findalldevs: %s", cString(&errbuf[0]))
	}
	defer freeAllDevsProc.Call(uintptr(unsafe.Pointer(head)))
	devices := make([]Device, 0, 8)
	for current := head; current != nil; current = current.next {
		if current.name == nil {
			continue
		}
		device := Device{Name: cString(current.name)}
		if current.description != nil {
			device.Description = cString(current.description)
		}
		devices = append(devices, device)
	}
	return devices, nil
}

func OpenLive(device string, snapLength, timeoutMillis int) (Source, error) {
	if device == "" {
		return nil, errors.New("Npcap interface name is empty")
	}
	if snapLength <= 0 || snapLength > maxPacketLength {
		snapLength = defaultSnapLength
	}
	if timeoutMillis <= 0 {
		timeoutMillis = pcapTimeoutMillis
	}
	if err := pcapDLL.Load(); err != nil {
		return nil, fmt.Errorf("load Npcap wpcap.dll: %w", err)
	}
	name, err := syscall.BytePtrFromString(device)
	if err != nil {
		return nil, err
	}
	errbuf := make([]byte, 256)
	handle, _, _ := openLiveProc.Call(
		uintptr(unsafe.Pointer(name)), uintptr(snapLength), 0,
		uintptr(timeoutMillis), uintptr(unsafe.Pointer(&errbuf[0])),
	)
	runtime.KeepAlive(name)
	if handle == 0 {
		return nil, fmt.Errorf("pcap_open_live(%q): %s", device, cString(&errbuf[0]))
	}
	linkType, _, _ := datalinkProc.Call(handle)
	return &liveSource{handle: handle, linkType: int(int32(linkType))}, nil
}

func (source *liveSource) ReadPacket(ctx context.Context) (Packet, error) {
	if source == nil || source.handle == 0 {
		return Packet{}, errors.New("Npcap source is closed")
	}
	for {
		select {
		case <-ctx.Done():
			return Packet{}, ctx.Err()
		default:
		}
		var header *packetHeader
		var data *byte
		result, _, _ := nextExProc.Call(source.handle, uintptr(unsafe.Pointer(&header)), uintptr(unsafe.Pointer(&data)))
		switch int32(result) {
		case 1:
			if header == nil || data == nil || header.capturedLen == 0 || header.capturedLen > maxPacketLength {
				return Packet{}, errors.New("Npcap returned invalid packet bounds")
			}
			copyData := append([]byte(nil), unsafe.Slice(data, int(header.capturedLen))...)
			stamp := time.Unix(int64(header.seconds), int64(header.microseconds)*int64(time.Microsecond)).UTC()
			return Packet{Timestamp: stamp, LinkType: source.linkType, Data: copyData}, nil
		case 0: // Read timeout; re-check context.
			continue
		case -1:
			return Packet{}, errors.New("Npcap packet read failed")
		case -2:
			return Packet{}, errors.New("Npcap capture ended")
		default:
			return Packet{}, fmt.Errorf("Npcap returned unexpected status %d", int32(result))
		}
	}
}

func (source *liveSource) Close() error {
	if source == nil || source.handle == 0 {
		return nil
	}
	closeProc.Call(source.handle)
	source.handle = 0
	return nil
}

func cString(pointer *byte) string {
	if pointer == nil {
		return ""
	}
	length := 0
	for length < 4096 && *(*byte)(unsafe.Add(unsafe.Pointer(pointer), length)) != 0 {
		length++
	}
	return string(unsafe.Slice(pointer, length))
}
