//go:build windows

// Package procinfo resolves the owning process (PID) of a TCP connection using
// the Windows IP Helper API (GetExtendedTcpTable), for both IPv4 and IPv6.
package procinfo

import (
	"encoding/binary"
	"fmt"
	"net"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	afInet              = 2
	afInet6             = 23
	tcpTableOwnerPIDAll = 5
	tcpStateListen      = 2
	udpTableOwnerPID    = 1
)

var (
	modIPHlp                = windows.NewLazyDLL("iphlpapi.dll")
	procGetExtendedTcpTable = modIPHlp.NewProc("GetExtendedTcpTable")
	procGetExtendedUdpTable = modIPHlp.NewProc("GetExtendedUdpTable")
)

// row is a parsed TCP table entry (IPv4 or IPv6).
type row struct {
	state      uint32
	localIP    net.IP
	localPort  uint16
	remoteIP   net.IP
	remotePort uint16
	pid        uint32
}

func getTCPTable(af int) ([]row, error) {
	var size uint32
	procGetExtendedTcpTable.Call(0, uintptr(unsafe.Pointer(&size)), 0, uintptr(af), tcpTableOwnerPIDAll, 0)
	if size == 0 {
		return nil, nil
	}
	buf := make([]byte, size)
	r, _, _ := procGetExtendedTcpTable.Call(
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&size)),
		0, uintptr(af), tcpTableOwnerPIDAll, 0,
	)
	if r != 0 {
		return nil, fmt.Errorf("GetExtendedTcpTable(af=%d) failed: %d", af, r)
	}
	if len(buf) < 4 {
		return nil, nil
	}
	n := binary.LittleEndian.Uint32(buf[0:4])
	rows := make([]row, 0, n)
	if af == afInet {
		// MIB_TCPROW_OWNER_PID: 24 bytes.
		off := 4
		for i := uint32(0); i < n && off+24 <= len(buf); i++ {
			rec := buf[off : off+24]
			rows = append(rows, row{
				state:      binary.LittleEndian.Uint32(rec[0:4]),
				localIP:    net.IP(append([]byte(nil), rec[4:8]...)),
				localPort:  binary.BigEndian.Uint16(rec[8:10]),
				remoteIP:   net.IP(append([]byte(nil), rec[12:16]...)),
				remotePort: binary.BigEndian.Uint16(rec[16:18]),
				pid:        binary.LittleEndian.Uint32(rec[20:24]),
			})
			off += 24
		}
	} else {
		// MIB_TCP6ROW_OWNER_PID: 56 bytes.
		off := 4
		for i := uint32(0); i < n && off+56 <= len(buf); i++ {
			rec := buf[off : off+56]
			rows = append(rows, row{
				localIP:    net.IP(append([]byte(nil), rec[0:16]...)),
				localPort:  binary.BigEndian.Uint16(rec[20:22]),
				remoteIP:   net.IP(append([]byte(nil), rec[24:40]...)),
				remotePort: binary.BigEndian.Uint16(rec[44:46]),
				state:      binary.LittleEndian.Uint32(rec[48:52]),
				pid:        binary.LittleEndian.Uint32(rec[52:56]),
			})
			off += 56
		}
	}
	return rows, nil
}

func afFor(ip net.IP) int {
	if ip.To4() != nil {
		return afInet
	}
	return afInet6
}

// OwnerPIDOutbound finds the PID that owns an outbound connection identified by
// its local and remote endpoints. Returns 0 if not found.
func OwnerPIDOutbound(localIP net.IP, localPort uint16, remoteIP net.IP, remotePort uint16) uint32 {
	rows, err := getTCPTable(afFor(localIP))
	if err != nil {
		return 0
	}
	var fallback uint32
	for _, r := range rows {
		if r.localPort != localPort || !r.localIP.Equal(localIP) {
			continue
		}
		if r.remoteIP.Equal(remoteIP) && r.remotePort == remotePort {
			return r.pid // exact 4-tuple match (SYN_SENT/ESTABLISHED)
		}
		if fallback == 0 {
			fallback = r.pid
		}
	}
	return fallback
}

// OwnerPIDListener finds the PID of the process listening on localPort (for
// inbound connections). Returns 0 if there is no such listener.
func OwnerPIDListener(localIP net.IP, localPort uint16) uint32 {
	rows, err := getTCPTable(afFor(localIP))
	if err != nil {
		return 0
	}
	for _, r := range rows {
		if r.state == tcpStateListen && r.localPort == localPort {
			return r.pid
		}
	}
	return 0
}

// udpRow is a parsed UDP table entry (local endpoint + owning PID).
type udpRow struct {
	localIP   net.IP
	localPort uint16
	pid       uint32
}

func getUDPTable(af int) ([]udpRow, error) {
	var size uint32
	procGetExtendedUdpTable.Call(0, uintptr(unsafe.Pointer(&size)), 0, uintptr(af), udpTableOwnerPID, 0)
	if size == 0 {
		return nil, nil
	}
	buf := make([]byte, size)
	r, _, _ := procGetExtendedUdpTable.Call(
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&size)),
		0, uintptr(af), udpTableOwnerPID, 0,
	)
	if r != 0 || len(buf) < 4 {
		return nil, fmt.Errorf("GetExtendedUdpTable(af=%d) failed: %d", af, r)
	}
	n := binary.LittleEndian.Uint32(buf[0:4])
	rows := make([]udpRow, 0, n)
	if af == afInet {
		// MIB_UDPROW_OWNER_PID: 12 bytes.
		off := 4
		for i := uint32(0); i < n && off+12 <= len(buf); i++ {
			rec := buf[off : off+12]
			rows = append(rows, udpRow{
				localIP:   net.IP(append([]byte(nil), rec[0:4]...)),
				localPort: binary.BigEndian.Uint16(rec[4:6]),
				pid:       binary.LittleEndian.Uint32(rec[8:12]),
			})
			off += 12
		}
	} else {
		// MIB_UDP6ROW_OWNER_PID: 28 bytes.
		off := 4
		for i := uint32(0); i < n && off+28 <= len(buf); i++ {
			rec := buf[off : off+28]
			rows = append(rows, udpRow{
				localIP:   net.IP(append([]byte(nil), rec[0:16]...)),
				localPort: binary.BigEndian.Uint16(rec[20:22]),
				pid:       binary.LittleEndian.Uint32(rec[24:28]),
			})
			off += 28
		}
	}
	return rows, nil
}

// OwnerPIDUDP finds the PID that owns a UDP socket bound to localPort. UDP
// sockets often bind the wildcard address, so a port match with an unspecified
// or equal local address wins. Returns 0 if not found.
func OwnerPIDUDP(localIP net.IP, localPort uint16) uint32 {
	rows, err := getUDPTable(afFor(localIP))
	if err != nil {
		return 0
	}
	var fallback uint32
	for _, r := range rows {
		if r.localPort != localPort {
			continue
		}
		if r.localIP.Equal(localIP) {
			return r.pid
		}
		if r.localIP.IsUnspecified() && fallback == 0 {
			fallback = r.pid
		}
	}
	return fallback
}
