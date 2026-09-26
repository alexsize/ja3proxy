//go:build linux

package pcap

import (
	"context"
	"errors"
	"fmt"
	"net"
	"syscall"
	"time"
)

const linuxCaptureTimeout = 200 * time.Millisecond

type linuxSource struct {
	fd   int
	data []byte
}

func ListDevices() ([]Device, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("list network interfaces: %w", err)
	}
	devices := make([]Device, 0, len(interfaces))
	for _, iface := range interfaces {
		devices = append(devices, Device{Name: iface.Name})
	}
	return devices, nil
}

func OpenLive(device string, snapLength, timeoutMillis int) (Source, error) {
	iface, err := net.InterfaceByName(device)
	if err != nil {
		return nil, fmt.Errorf("find capture interface %q: %w", device, err)
	}
	if snapLength <= 0 || snapLength > maxPacketLength {
		snapLength = defaultSnapLength
	}
	if timeoutMillis <= 0 {
		timeoutMillis = int(linuxCaptureTimeout / time.Millisecond)
	}
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(0x0003))) // ETH_P_ALL
	if err != nil {
		return nil, fmt.Errorf("open raw packet capture socket: %w", err)
	}
	closeOnError := true
	defer func() {
		if closeOnError {
			_ = syscall.Close(fd)
		}
	}()
	if err := syscall.Bind(fd, &syscall.SockaddrLinklayer{Protocol: htons(0x0003), Ifindex: iface.Index}); err != nil {
		return nil, fmt.Errorf("bind capture socket to %q: %w", device, err)
	}
	timeout := syscall.NsecToTimeval(int64(timeoutMillis) * int64(time.Millisecond))
	if err := syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &timeout); err != nil {
		return nil, fmt.Errorf("set capture socket timeout: %w", err)
	}
	closeOnError = false
	return &linuxSource{fd: fd, data: make([]byte, snapLength)}, nil
}

func (source *linuxSource) ReadPacket(ctx context.Context) (Packet, error) {
	if source == nil || source.fd < 0 {
		return Packet{}, errors.New("packet capture source is closed")
	}
	for {
		if err := ctx.Err(); err != nil {
			return Packet{}, err
		}
		n, address, err := syscall.Recvfrom(source.fd, source.data, 0)
		if err == syscall.EAGAIN || err == syscall.EWOULDBLOCK || err == syscall.EINTR {
			continue
		}
		if err != nil {
			return Packet{}, fmt.Errorf("read captured packet: %w", err)
		}
		if n <= 0 {
			continue
		}
		linkType := linkTypeForHardware(address)
		return Packet{Timestamp: time.Now().UTC(), LinkType: linkType, Data: append([]byte(nil), source.data[:n]...)}, nil
	}
}

func (source *linuxSource) Close() error {
	if source == nil || source.fd < 0 {
		return nil
	}
	err := syscall.Close(source.fd)
	source.fd = -1
	return err
}

func htons(value uint16) uint16 { return value<<8 | value>>8 }

func linkTypeForHardware(address syscall.Sockaddr) int {
	link, ok := address.(*syscall.SockaddrLinklayer)
	if ok && (link.Hatype == 772 || link.Hatype == 65534) { // loopback or no link-layer header
		return 101 // DLT_RAW
	}
	return 1 // DLT_EN10MB
}
