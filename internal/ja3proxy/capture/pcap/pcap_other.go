//go:build !windows && !linux

package pcap

import "context"

type unsupportedSource struct{}

func ListDevices() ([]Device, error) { return nil, ErrUnsupported }

func OpenLive(string, int, int) (Source, error) { return nil, ErrUnsupported }

func (unsupportedSource) ReadPacket(context.Context) (Packet, error) { return Packet{}, ErrUnsupported }

func (unsupportedSource) Close() error { return nil }
