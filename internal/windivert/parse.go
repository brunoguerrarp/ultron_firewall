//go:build windows

package windivert

import (
	"encoding/binary"
	"net"
)

// TCP flag bits.
const (
	tcpFlagFIN = 0x01
	tcpFlagSYN = 0x02
	tcpFlagRST = 0x04
	tcpFlagACK = 0x10
)

// PacketInfo holds the fields we extract from a captured IP + TCP/UDP packet.
type PacketInfo struct {
	IPVersion int
	Protocol  uint8
	SrcIP     net.IP
	DstIP     net.IP
	SrcPort   uint16
	DstPort   uint16
	SYN       bool
	ACK       bool
	RST       bool
	// L4PayloadOffset is the index in the packet where the UDP payload begins
	// (0 if not applicable). Used to snoop DNS responses.
	L4PayloadOffset int
}

// ParsePacket extracts IPv4/IPv6 + TCP/UDP fields from a raw captured packet.
// It returns ok=false for anything it doesn't understand (caller should then
// just re-inject the packet untouched).
func ParsePacket(pkt []byte) (PacketInfo, bool) {
	var info PacketInfo
	if len(pkt) < 20 {
		return info, false
	}
	version := pkt[0] >> 4
	var l4off int
	switch version {
	case 4:
		ihl := int(pkt[0]&0x0f) * 4
		if ihl < 20 || len(pkt) < ihl {
			return info, false
		}
		info.IPVersion = 4
		info.Protocol = pkt[9]
		info.SrcIP = net.IP(append([]byte(nil), pkt[12:16]...))
		info.DstIP = net.IP(append([]byte(nil), pkt[16:20]...))
		l4off = ihl
	case 6:
		if len(pkt) < 40 {
			return info, false
		}
		info.IPVersion = 6
		info.Protocol = pkt[6] // next header; no extension-header walking (MVP)
		info.SrcIP = net.IP(append([]byte(nil), pkt[8:24]...))
		info.DstIP = net.IP(append([]byte(nil), pkt[24:40]...))
		l4off = 40
	default:
		return info, false
	}

	l4 := pkt[l4off:]
	switch info.Protocol {
	case ProtoTCP:
		if len(l4) < 20 {
			return info, false
		}
		info.SrcPort = binary.BigEndian.Uint16(l4[0:2])
		info.DstPort = binary.BigEndian.Uint16(l4[2:4])
		flags := l4[13]
		info.SYN = flags&tcpFlagSYN != 0
		info.ACK = flags&tcpFlagACK != 0
		info.RST = flags&tcpFlagRST != 0
	case ProtoUDP:
		if len(l4) < 8 {
			return info, false
		}
		info.SrcPort = binary.BigEndian.Uint16(l4[0:2])
		info.DstPort = binary.BigEndian.Uint16(l4[2:4])
		info.L4PayloadOffset = l4off + 8 // UDP header is 8 bytes
	default:
		return info, false
	}
	return info, true
}
