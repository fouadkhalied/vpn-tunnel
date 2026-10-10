//go:build linux

// Package tun wraps a Linux TUN device (layer 3: raw IP packets).
//
// Course: Chapter 1, lesson "TUN/TAP Interfaces".
package tun

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"syscall"
	"unsafe"
)

const (
	devicePath = "/dev/net/tun"
	ifNameSize = 16     // IFNAMSIZ: 15 usable characters + a terminating zero
	iffTUN     = 0x0001 // layer 3 (IP packets). TAP would be 0x0002
	iffNoPI    = 0x1000 // don't prepend the 4-byte packet-info header
	tunSetIff  = 0x400454ca
)

// ErrNameTooLong is returned when the interface name doesn't fit in the kernel's limit.
var ErrNameTooLong = errors.New("tun: interface name too long")

// ifreq mirrors the kernel's struct ifreq. The kernel expects it to be 40 bytes.
type ifreq struct {
	name  [ifNameSize]byte // interface name, padded with zeros
	flags uint16           // iffTUN | iffNoPI
	_     [22]byte         // padding up to 40 bytes
}

// newIfreq validates the name and builds the request for the kernel.
// An empty name is allowed: the kernel then picks one (tun0, tun1, ...).
func newIfreq(name string) (ifreq, error) {
	var req ifreq
	if len(name) >= ifNameSize {
		return req, fmt.Errorf("%w: %q is %d bytes, the maximum is %d",
			ErrNameTooLong, name, len(name), ifNameSize-1)
	}
	if bytes.IndexByte([]byte(name), 0) >= 0 {
		return req, fmt.Errorf("tun: interface name %q contains a zero byte", name)
	}
	copy(req.name[:], name)
	req.flags = iffTUN | iffNoPI
	return req, nil
}

// ifName returns the interface name stored in the request, up to the first zero byte.
func (r *ifreq) ifName() string {
	n := bytes.IndexByte(r.name[:], 0)
	if n < 0 {
		n = len(r.name)
	}
	return string(r.name[:n])
}

// explain wraps err with context, and adds a hint when it's a permission problem.
func explain(op string, err error) error {
	if errors.Is(err, os.ErrPermission) {
		return fmt.Errorf("tun: %s: %w (needs root or CAP_NET_ADMIN)", op, err)
	}
	return fmt.Errorf("tun: %s: %w", op, err)
}

// Device is an open TUN interface.
type Device struct {
	file *os.File
	name string
}

// Open creates a TUN interface called name, e.g. "wg0".
// It needs root or CAP_NET_ADMIN. The interface disappears when the Device is closed
// (or the program exits).
func Open(name string) (*Device, error) {
	req, err := newIfreq(name)
	if err != nil {
		return nil, err
	}

	file, err := os.OpenFile(devicePath, os.O_RDWR, 0)
	if err != nil {
		return nil, explain("open "+devicePath, err)
	}

	_, _, errno := syscall.Syscall(
		syscall.SYS_IOCTL,
		file.Fd(),
		tunSetIff,
		uintptr(unsafe.Pointer(&req)),
	)
	if errno != 0 {
		_ = file.Close()
		return nil, explain(fmt.Sprintf("create interface %q", name), errno)
	}

	// The kernel writes the real name back (it picks one if we asked for "").
	return &Device{file: file, name: req.ifName()}, nil
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
