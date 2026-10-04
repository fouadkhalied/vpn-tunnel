//go:build linux

// Package tun wraps a Linux TUN device (layer 3: raw IP packets).
//
// Course: Chapter 1, lesson "TUN/TAP Interfaces".
package tun

import (
	"errors"
	"os"
)

const (
	devicePath = "/dev/net/tun"
	ifNameSize = 16     // IFNAMSIZ
	iffTUN     = 0x0001 // layer 3 (IP packets). TAP would be 0x0002
	iffNoPI    = 0x1000 // don't prepend the 4-byte packet-info header
	tunSetIff  = 0x400454ca
)

var errNotImplemented = errors.New("not implemented")

// Device is an open TUN interface.
type Device struct {
	file *os.File
	name string
}

// Open creates (or attaches to) a TUN interface called name, e.g. "wg0".
//
// TODO:
//  1. os.OpenFile(devicePath, os.O_RDWR, 0)
//  2. Build the ifreq struct: 16 bytes of name (NUL padded) + uint16 flags,
//     padded out to 40 bytes. Flags = iffTUN | iffNoPI.
//  3. ioctl(fd, tunSetIff, &ifreq) via syscall.Syscall(syscall.SYS_IOCTL, ...)
//  4. Store the name the kernel returns in the ifreq.
//
// This is the Go version of the Python snippet from lesson 1.
func Open(name string) (*Device, error) {
	_ = name
	return nil, errNotImplemented
}

// Read blocks until the kernel hands us one outbound IP packet.
// buf must be big enough for the MTU (use 65536 while learning).
func (d *Device) Read(buf []byte) (int, error) {
	return d.file.Read(buf) // revisit in the Performance lesson
}

// Write injects one IP packet into the kernel as if it arrived from the network.
func (d *Device) Write(pkt []byte) (int, error) {
	return d.file.Write(pkt)
}

func (d *Device) Name() string { return d.name }

func (d *Device) Close() error { return d.file.Close() }
