//go:build windows

// Package windivert is a small, cgo-free binding to the WinDivert 2.2 user-mode
// API. It exposes just what Ultron Firewall needs: opening a SOCKET-layer
// handle, receiving socket events (CONNECT/ACCEPT) with process and endpoint
// information, and allowing (re-injecting) or blocking (not re-injecting) them.
//
// The WinDivert DLL and signed driver are embedded in the binary (see
// assets.go) and extracted at runtime, so the application ships as a single
// executable. Administrator rights are required to load the driver.
package windivert

import (
	"fmt"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Layers.
const (
	LayerNetwork        = 0
	LayerNetworkForward = 1
	LayerFlow           = 2
	LayerSocket         = 3
	LayerReflect        = 4
)

// Events.
const (
	EventNetworkPacket   = 0
	EventFlowEstablished = 1
	EventFlowDeleted     = 2
	EventSocketBind      = 3
	EventSocketConnect   = 4
	EventSocketListen    = 5
	EventSocketAccept    = 6
	EventSocketClose     = 7
	EventReflectOpen     = 8
	EventReflectClose    = 9
)

// Flags.
const (
	FlagSniff     = 0x0001
	FlagDrop      = 0x0002
	FlagRecvOnly  = 0x0004
	FlagSendOnly  = 0x0008
	FlagNoInstall = 0x0010
	FlagFragments = 0x0020
)

// Shutdown modes.
const (
	ShutdownRecv = 0x1
	ShutdownSend = 0x2
	ShutdownBoth = 0x3
)

// Protocol numbers.
const (
	ProtoTCP = 6
	ProtoUDP = 17
)

const invalidHandle = ^uintptr(0)

// Address mirrors WINDIVERT_ADDRESS (80 bytes).
type Address struct {
	Timestamp int64
	flags     uint32 // Layer:8 Event:8 Sniffed:1 Outbound:1 Loopback:1 Impostor:1 IPv6:1 IPChecksum:1 TCPChecksum:1 UDPChecksum:1 Reserved1:8
	Reserved2 uint32
	union     [64]byte
}

func (a *Address) Layer() uint8   { return uint8(a.flags & 0xFF) }
func (a *Address) Event() uint8   { return uint8((a.flags >> 8) & 0xFF) }
func (a *Address) Sniffed() bool  { return (a.flags>>16)&1 != 0 }
func (a *Address) Outbound() bool { return (a.flags>>17)&1 != 0 }
func (a *Address) Loopback() bool { return (a.flags>>18)&1 != 0 }
func (a *Address) IPv6() bool     { return (a.flags>>20)&1 != 0 }

// SocketData mirrors WINDIVERT_DATA_SOCKET (overlaid on the address union).
type SocketData struct {
	EndpointID       uint64
	ParentEndpointID uint64
	ProcessID        uint32
	LocalAddr        [4]uint32
	RemoteAddr       [4]uint32
	LocalPort        uint16
	RemotePort       uint16
	Protocol         uint8
	_                [7]byte
}

// Socket returns the socket-layer view of the address.
func (a *Address) Socket() *SocketData {
	return (*SocketData)(unsafe.Pointer(&a.union[0]))
}

// LocalIP returns the formatted local address.
func (a *Address) LocalIP() string {
	s := a.Socket()
	if a.IPv6() {
		return formatIPv6(&s.LocalAddr)
	}
	return formatIPv4(s.LocalAddr[0])
}

// RemoteIP returns the formatted remote address.
func (a *Address) RemoteIP() string {
	s := a.Socket()
	if a.IPv6() {
		return formatIPv6(&s.RemoteAddr)
	}
	return formatIPv4(s.RemoteAddr[0])
}

// Handle wraps an open WinDivert handle.
type Handle struct {
	h       uintptr
	sendMu  sync.Mutex
	closeMu sync.Mutex
	closed  bool
}

var (
	dll          *windows.LazyDLL
	procOpen     *windows.LazyProc
	procRecv     *windows.LazyProc
	procSend     *windows.LazyProc
	procClose    *windows.LazyProc
	procSetParam *windows.LazyProc
	procShutdown *windows.LazyProc
	procFmtIPv4  *windows.LazyProc
	procFmtIPv6  *windows.LazyProc
	procCompile  *windows.LazyProc

	loadOnce sync.Once
	loadErr  error
)

func load() error {
	loadOnce.Do(func() {
		dllPath, err := extractBinaries()
		if err != nil {
			loadErr = fmt.Errorf("extracting WinDivert: %w", err)
			return
		}
		dll = windows.NewLazyDLL(dllPath)
		if err := dll.Load(); err != nil {
			loadErr = fmt.Errorf("loading WinDivert.dll from %s: %w", dllPath, err)
			return
		}
		procOpen = dll.NewProc("WinDivertOpen")
		procRecv = dll.NewProc("WinDivertRecv")
		procSend = dll.NewProc("WinDivertSend")
		procClose = dll.NewProc("WinDivertClose")
		procSetParam = dll.NewProc("WinDivertSetParam")
		procShutdown = dll.NewProc("WinDivertShutdown")
		procFmtIPv4 = dll.NewProc("WinDivertHelperFormatIPv4Address")
		procFmtIPv6 = dll.NewProc("WinDivertHelperFormatIPv6Address")
		procCompile = dll.NewProc("WinDivertHelperCompileFilter")
	})
	return loadErr
}

// CompileFilter validates a filter string for the given layer without opening a
// handle (user-mode only; no driver or admin rights needed). It returns a
// descriptive error if the filter is invalid.
func CompileFilter(filter string, layer int) error {
	if err := load(); err != nil {
		return err
	}
	fb, err := windows.BytePtrFromString(filter)
	if err != nil {
		return err
	}
	var obj [2048]byte
	var errStr *byte
	var errPos uint32
	r, _, _ := procCompile.Call(
		uintptr(unsafe.Pointer(fb)),
		uintptr(layer),
		uintptr(unsafe.Pointer(&obj[0])),
		uintptr(len(obj)),
		uintptr(unsafe.Pointer(&errStr)),
		uintptr(unsafe.Pointer(&errPos)),
	)
	if r == 0 {
		msg := ""
		if errStr != nil {
			msg = windows.BytePtrToString(errStr)
		}
		return fmt.Errorf("invalid filter at position %d: %s", errPos, msg)
	}
	return nil
}

// Available reports whether the WinDivert DLL/driver can be loaded. It does not
// open a handle (which additionally requires administrator rights).
func Available() error { return load() }

// Open opens a WinDivert handle on the given layer with the given filter.
func Open(filter string, layer, priority int, flags uint64) (*Handle, error) {
	if err := load(); err != nil {
		return nil, err
	}
	fb, err := windows.BytePtrFromString(filter)
	if err != nil {
		return nil, err
	}
	r, _, callErr := procOpen.Call(
		uintptr(unsafe.Pointer(fb)),
		uintptr(layer),
		uintptr(uint16(int16(priority))),
		uintptr(flags),
	)
	if r == invalidHandle {
		return nil, fmt.Errorf("WinDivertOpen failed: %w", callErr)
	}
	return &Handle{h: r}, nil
}

// Recv blocks until a socket event is captured, filling addr. For the SOCKET
// layer there is no packet payload.
func (h *Handle) Recv(addr *Address) error {
	r, _, callErr := procRecv.Call(
		h.h,
		0, // pPacket
		0, // packetLen
		0, // pRecvLen
		uintptr(unsafe.Pointer(addr)),
	)
	if r == 0 {
		return fmt.Errorf("WinDivertRecv failed: %w", callErr)
	}
	return nil
}

// Allow re-injects a captured event, letting the socket operation proceed.
func (h *Handle) Allow(addr *Address) error {
	h.sendMu.Lock()
	defer h.sendMu.Unlock()
	r, _, callErr := procSend.Call(
		h.h,
		0, // pPacket
		0, // packetLen
		0, // pSendLen
		uintptr(unsafe.Pointer(addr)),
	)
	if r == 0 {
		return fmt.Errorf("WinDivertSend failed: %w", callErr)
	}
	return nil
}

// RecvPacket blocks until a packet is captured, copying it into buf and filling
// addr. It returns the number of bytes written to buf.
func (h *Handle) RecvPacket(buf []byte, addr *Address) (int, error) {
	var recvLen uint32
	var pkt uintptr
	if len(buf) > 0 {
		pkt = uintptr(unsafe.Pointer(&buf[0]))
	}
	r, _, callErr := procRecv.Call(
		h.h,
		pkt,
		uintptr(len(buf)),
		uintptr(unsafe.Pointer(&recvLen)),
		uintptr(unsafe.Pointer(addr)),
	)
	if r == 0 {
		return 0, fmt.Errorf("WinDivertRecv failed: %w", callErr)
	}
	return int(recvLen), nil
}

// SendPacket re-injects a captured packet, letting it proceed. Used at the
// NETWORK layer to "allow" a pended connection.
func (h *Handle) SendPacket(buf []byte, addr *Address) error {
	h.sendMu.Lock()
	defer h.sendMu.Unlock()
	var sendLen uint32
	var pkt uintptr
	if len(buf) > 0 {
		pkt = uintptr(unsafe.Pointer(&buf[0]))
	}
	r, _, callErr := procSend.Call(
		h.h,
		pkt,
		uintptr(len(buf)),
		uintptr(unsafe.Pointer(&sendLen)),
		uintptr(unsafe.Pointer(addr)),
	)
	if r == 0 {
		return fmt.Errorf("WinDivertSend failed: %w", callErr)
	}
	return nil
}

// SetParam sets a handle parameter (e.g. queue length/time/size).
func (h *Handle) SetParam(param int, value uint64) error {
	r, _, callErr := procSetParam.Call(h.h, uintptr(param), uintptr(value))
	if r == 0 {
		return fmt.Errorf("WinDivertSetParam failed: %w", callErr)
	}
	return nil
}

// Shutdown stops the handle from queuing further events and unblocks Recv.
func (h *Handle) Shutdown(how int) error {
	r, _, callErr := procShutdown.Call(h.h, uintptr(how))
	if r == 0 {
		return fmt.Errorf("WinDivertShutdown failed: %w", callErr)
	}
	return nil
}

// Close closes the handle. On the last close the driver is unloaded.
func (h *Handle) Close() error {
	h.closeMu.Lock()
	defer h.closeMu.Unlock()
	if h.closed {
		return nil
	}
	h.closed = true
	r, _, callErr := procClose.Call(h.h)
	if r == 0 {
		return fmt.Errorf("WinDivertClose failed: %w", callErr)
	}
	return nil
}

func formatIPv4(addr uint32) string {
	var buf [64]byte
	r, _, _ := procFmtIPv4.Call(uintptr(addr), uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
	if r == 0 {
		return ""
	}
	return cstr(buf[:])
}

func formatIPv6(addr *[4]uint32) string {
	var buf [64]byte
	r, _, _ := procFmtIPv6.Call(uintptr(unsafe.Pointer(addr)), uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
	if r == 0 {
		return ""
	}
	return cstr(buf[:])
}

func cstr(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}
