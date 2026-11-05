//go:build windows

package engine

import (
	"encoding/binary"
	"net"
	"strings"
)

// parseDNSResponse parses a DNS message (UDP payload) and returns the first
// question name (lowercased, no trailing dot), the A/AAAA answer IPs, and the
// smallest answer TTL in seconds. It is defensive: any malformed input yields
// empty results rather than a panic.
func parseDNSResponse(msg []byte) (qname string, ips []string, minTTL uint32) {
	if len(msg) < 12 {
		return "", nil, 0
	}
	qd := int(binary.BigEndian.Uint16(msg[4:6]))
	an := int(binary.BigEndian.Uint16(msg[6:8]))
	off := 12

	for i := 0; i < qd; i++ {
		name, next, ok := readDNSName(msg, off)
		if !ok || next+4 > len(msg) {
			return "", nil, 0
		}
		if i == 0 {
			qname = strings.ToLower(strings.TrimSuffix(name, "."))
		}
		off = next + 4 // QTYPE(2) + QCLASS(2)
	}

	ttlSet := false
	for i := 0; i < an; i++ {
		_, next, ok := readDNSName(msg, off)
		if !ok || next+10 > len(msg) {
			break
		}
		typ := binary.BigEndian.Uint16(msg[next : next+2])
		ttl := binary.BigEndian.Uint32(msg[next+4 : next+8])
		rdlen := int(binary.BigEndian.Uint16(msg[next+8 : next+10]))
		rdata := next + 10
		if rdata+rdlen > len(msg) {
			break
		}
		switch typ {
		case 1: // A
			if rdlen == 4 {
				ips = append(ips, net.IP(append([]byte(nil), msg[rdata:rdata+4]...)).String())
				if !ttlSet || ttl < minTTL {
					minTTL, ttlSet = ttl, true
				}
			}
		case 28: // AAAA
			if rdlen == 16 {
				ips = append(ips, net.IP(append([]byte(nil), msg[rdata:rdata+16]...)).String())
				if !ttlSet || ttl < minTTL {
					minTTL, ttlSet = ttl, true
				}
			}
		}
		off = rdata + rdlen
	}
	return qname, ips, minTTL
}

// readDNSName reads a (possibly compressed) DNS name starting at off. It returns
// the dotted name, the offset in the record stream just past the name (after
// the terminating zero or the 2-byte pointer), and ok.
func readDNSName(msg []byte, off int) (string, int, bool) {
	var labels []string
	jumped := false
	next := off
	steps := 0
	for {
		if off >= len(msg) || steps > 128 {
			return "", 0, false
		}
		steps++
		b := msg[off]
		if b == 0 {
			off++
			if !jumped {
				next = off
			}
			break
		}
		if b&0xC0 == 0xC0 { // compression pointer
			if off+1 >= len(msg) {
				return "", 0, false
			}
			ptr := int(binary.BigEndian.Uint16(msg[off:off+2]) & 0x3FFF)
			if !jumped {
				next = off + 2
			}
			jumped = true
			off = ptr
			continue
		}
		l := int(b)
		off++
		if off+l > len(msg) {
			return "", 0, false
		}
		labels = append(labels, string(msg[off:off+l]))
		off += l
	}
	return strings.Join(labels, "."), next, true
}

// domainMatches reports whether qname equals or is a subdomain of any of the
// configured domains (suffix match).
func domainMatches(qname string, domains []string) bool {
	if qname == "" {
		return false
	}
	for _, d := range domains {
		d = strings.ToLower(strings.TrimSpace(strings.TrimSuffix(d, ".")))
		if d == "" {
			continue
		}
		if qname == d || strings.HasSuffix(qname, "."+d) {
			return true
		}
	}
	return false
}
