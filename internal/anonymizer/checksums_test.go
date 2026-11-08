package anonymizer

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

var testPacketID int64

func testPacket(t *testing.T, v6 bool, protocol string, payload []byte) gopacket.Packet {
	t.Helper()
	var network gopacket.SerializableLayer
	var nl gopacket.NetworkLayer
	var transport gopacket.SerializableLayer
	var next layers.IPProtocol
	switch protocol {
	case "udp":
		next = layers.IPProtocolUDP
		transport = &layers.UDP{SrcPort: 5060, DstPort: 5060}
	case "tcp":
		next = layers.IPProtocolTCP
		transport = &layers.TCP{SrcPort: 5060, DstPort: 5060, Seq: 100, ACK: true, Window: 4096}
	case "icmp":
		if v6 {
			next = layers.IPProtocolICMPv6
			transport = &layers.ICMPv6{TypeCode: layers.CreateICMPv6TypeCode(128, 0)}
		} else {
			next = layers.IPProtocolICMPv4
			transport = &layers.ICMPv4{TypeCode: layers.CreateICMPv4TypeCode(8, 0), Id: 123, Seq: 1}
		}
	}
	first := layers.LayerTypeIPv4
	if v6 {
		ip := &layers.IPv6{Version: 6, HopLimit: 64, NextHeader: next, SrcIP: net.ParseIP("2001:4860:1111::1"), DstIP: net.ParseIP("2001:4860:2222::2")}
		network = ip
		nl = ip
		first = layers.LayerTypeIPv6
	} else {
		ip := &layers.IPv4{Version: 4, TTL: 64, Protocol: next, SrcIP: net.IPv4(10, 40, 50, 60), DstIP: net.IPv4(8, 8, 4, 4)}
		network = ip
		nl = ip
	}
	if c, ok := transport.(interface {
		SetNetworkLayerForChecksum(gopacket.NetworkLayer) error
	}); ok {
		if e := c.SetNetworkLayerForChecksum(nl); e != nil {
			t.Fatal(e)
		}
	}
	b := gopacket.NewSerializeBuffer()
	if e := gopacket.SerializeLayers(b, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, network, transport, gopacket.Payload(payload)); e != nil {
		t.Fatal(e)
	}
	p := gopacket.NewPacket(b.Bytes(), first, gopacket.Default)
	testPacketID++
	p.Metadata().Timestamp = time.Unix(500, testPacketID)
	return p
}

// Independent Internet checksum oracle, including odd-length messages.
func sum16(data []byte) uint16 {
	var sum uint32
	for len(data) >= 2 {
		sum += uint32(data[0])<<8 | uint32(data[1])
		data = data[2:]
	}
	if len(data) > 0 {
		sum += uint32(data[0]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 65535) + (sum >> 16)
	}
	return ^uint16(sum)
}

func assertPacketChecksums(t *testing.T, p gopacket.Packet) {
	t.Helper()
	raw := p.Data()
	if cached := GetModifiedPacketData(p); cached != nil {
		raw = cached
	}
	v6 := raw[0]>>4 == 6
	offset := 20
	proto := raw[9]
	var pseudo []byte
	if v6 {
		offset = 40
		proto = raw[6]
		if int(binary.BigEndian.Uint16(raw[4:6])) != len(raw)-40 {
			t.Fatal("IPv6 length mismatch")
		}
		pseudo = append(pseudo, raw[8:40]...)
		pseudo = append(pseudo, 0, 0, byte((len(raw)-40)>>8), byte(len(raw)-40), 0, 0, 0, proto)
	} else {
		offset = int(raw[0]&15) * 4
		if int(binary.BigEndian.Uint16(raw[2:4])) != len(raw) {
			t.Fatal("IPv4 length mismatch")
		}
		if sum16(raw[:offset]) != 0 {
			t.Fatal("invalid IPv4 checksum")
		}
		if proto != 1 {
			pseudo = append(pseudo, raw[12:20]...)
			pseudo = append(pseudo, 0, proto, byte((len(raw)-offset)>>8), byte(len(raw)-offset))
		}
	}
	pseudo = append(pseudo, raw[offset:]...)
	if sum16(pseudo) != 0 {
		t.Fatalf("invalid transport checksum (IPv6=%v, protocol=%d)", v6, proto)
	}
	if proto == 17 && int(binary.BigEndian.Uint16(raw[offset+4:offset+6])) != len(raw)-offset {
		t.Fatal("UDP length mismatch")
	}
}

func TestChecksumsAfterAnonymization(t *testing.T) {
	for _, v6 := range []bool{false, true} {
		for _, proto := range []string{"udp", "tcp", "icmp"} {
			t.Run(proto+map[bool]string{false: "4", true: "6"}[v6], func(t *testing.T) {
				p := testPacket(t, v6, proto, []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10})
				ProcessNetworkLayer(p)
				UpdateChecksums(p)
				assertPacketChecksums(t, p)
			})
		}
	}
}

func TestChecksumsForModifiedSIP(t *testing.T) {
	for _, v6 := range []bool{false, true} {
		for _, proto := range []string{"udp", "tcp"} {
			t.Run(proto+map[bool]string{false: "4", true: "6"}[v6], func(t *testing.T) {
				p := testPacket(t, v6, proto, []byte("OPTIONS sip:alice@10.40.50.60 SIP/2.0\r\nContent-Length: 0\r\n\r\n"))
				Process(p, NewConfig())
				UpdateChecksums(p)
				assertPacketChecksums(t, p)
			})
		}
	}
}

func TestCalculateChecksum(t *testing.T) {
	for _, data := range [][]byte{nil, {1}, {0, 1, 0xf2, 3, 0xf4, 0xf5, 0xf6, 0xf7}, bytes.Repeat([]byte{255}, 101)} {
		if got, want := calculateChecksum(data), sum16(data); got != want {
			t.Fatalf("checksum=%x want %x", got, want)
		}
	}
	UpdateChecksums(gopacket.NewPacket(nil, layers.LayerTypeEthernet, gopacket.Default))
}
