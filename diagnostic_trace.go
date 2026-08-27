package pingtunnel

// TEMPORARY forensic instrumentation for the 2026-08-24 Android KCP/DNS
// investigation. It is deliberately observation-only and may be removed after
// the correlated capture has been collected.

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"
)

func diagEndpoint(sproto int) string {
	if sproto == SEND_PROTO {
		return "client"
	}
	return "server"
}

func diagDecodedEndpoint(rproto int32) string {
	if rproto < 0 {
		return "client"
	}
	return "server"
}

func diagIsDNS(target string, payload []byte) bool {
	_, port, err := net.SplitHostPort(target)
	return err == nil && port == "53" && len(payload) >= 12
}

func diagDNS(payload []byte) string {
	if len(payload) < 12 {
		return "dns_short"
	}
	id := binary.BigEndian.Uint16(payload[0:2])
	qr := (payload[2] & 0x80) != 0
	name := "?"
	if !qr {
		var labels []string
		for off := 12; off < len(payload); {
			n := int(payload[off])
			off++
			if n == 0 {
				name = strings.Join(labels, ".")
				break
			}
			if n&0xc0 != 0 || off+n > len(payload) {
				break
			}
			labels = append(labels, string(payload[off:off+n]))
			off += n
		}
	}
	kind := "request"
	if qr {
		kind = "response"
	}
	return fmt.Sprintf("dns_%s id=%d name=%s rcode=%d bytes=%d", kind, id, name, payload[3]&0x0f, len(payload))
}
