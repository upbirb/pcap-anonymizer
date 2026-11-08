package pcap

import (
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/upbirb/pcap-anonymizer/internal/anonymizer"
)

func fixture(t *testing.T, ng bool, n int) ([]byte, [][]byte) {
	t.Helper()
	var buf bytes.Buffer
	var write func(gopacket.CaptureInfo, []byte) error
	var flush func() error
	if ng {
		w, e := pcapgo.NewNgWriter(&buf, layers.LinkTypeEthernet)
		if e != nil {
			t.Fatal(e)
		}
		write = w.WritePacket
		flush = w.Flush
	} else {
		w := pcapgo.NewWriter(&buf)
		if e := w.WriteFileHeader(65536, layers.LinkTypeEthernet); e != nil {
			t.Fatal(e)
		}
		write = w.WritePacket
	}
	var data [][]byte
	for i := 0; i < n; i++ {
		// Large enough to cross the reader's buffer boundary.
		packet := make([]byte, 300)
		binary.BigEndian.PutUint16(packet[12:14], 0x88b5)
		packet[20] = byte(i)
		ci := gopacket.CaptureInfo{Timestamp: time.Unix(100, int64(i)*1000000), CaptureLength: len(packet), Length: len(packet)}
		if e := write(ci, packet); e != nil {
			t.Fatal(e)
		}
		data = append(data, packet)
	}
	if flush != nil {
		if e := flush(); e != nil {
			t.Fatal(e)
		}
	}
	return buf.Bytes(), data
}

func TestReadCaptureFormats(t *testing.T) {
	for _, ng := range []bool{false, true} {
		for _, compressed := range []bool{false, true} {
			name := map[bool]string{false: "pcap", true: "pcapng"}[ng]
			if compressed {
				name += ".gz"
			}
			t.Run(name, func(t *testing.T) {
				raw, want := fixture(t, ng, 40)
				if compressed {
					var b bytes.Buffer
					w := gzip.NewWriter(&b)
					if _, e := w.Write(raw); e != nil {
						t.Fatal(e)
					}
					if e := w.Close(); e != nil {
						t.Fatal(e)
					}
					raw = b.Bytes()
				}
				path := filepath.Join(t.TempDir(), name)
				if e := os.WriteFile(path, raw, 0600); e != nil {
					t.Fatal(e)
				}
				got, e := ReadPackets(path)
				if e != nil {
					t.Fatal(e)
				}
				if len(got) != len(want) {
					t.Fatalf("packets=%d, want %d", len(got), len(want))
				}
				for i, p := range got {
					if !bytes.Equal(p.Data(), want[i]) {
						t.Fatalf("packet %d corrupted", i)
					}
					if !p.Metadata().Timestamp.Equal(time.Unix(100, int64(i)*1000000)) {
						t.Fatalf("timestamp %d changed", i)
					}
				}
			})
		}
	}
}

func TestReadInvalidCaptures(t *testing.T) {
	raw, _ := fixture(t, false, 1)
	for name, data := range map[string][]byte{"empty": {}, "short": {1, 2}, "unknown": {1, 2, 3, 4}, "header": raw[:12], "truncated": raw[:len(raw)-1], "bad-gzip": {0x1f, 0x8b, 0, 0}} {
		t.Run(name, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), name)
			if e := os.WriteFile(p, data, 0600); e != nil {
				t.Fatal(e)
			}
			if _, e := ReadPackets(p); e == nil {
				t.Fatal("expected an error")
			}
		})
	}
	if _, e := ReadPackets(filepath.Join(t.TempDir(), "missing")); e == nil {
		t.Fatal("missing file accepted")
	}
}

func TestWriteRoundTrip(t *testing.T) {
	raw, want := fixture(t, false, 40)
	packets, e := readPcap(bytes.NewReader(raw))
	if e != nil {
		t.Fatal(e)
	}
	path := filepath.Join(t.TempDir(), "out.pcap")
	if e := WritePackets(path, packets); e != nil {
		t.Fatal(e)
	}
	// Independent reader avoids hiding matching reader/writer bugs.
	f, e := os.Open(path)
	if e != nil {
		t.Fatal(e)
	}
	defer f.Close()
	r, e := pcapgo.NewReader(f)
	if e != nil {
		t.Fatal(e)
	}
	for i, data := range want {
		got, ci, e := r.ReadPacketData()
		if e != nil {
			t.Fatal(e)
		}
		if !bytes.Equal(got, data) || !ci.Timestamp.Equal(packets[i].Metadata().Timestamp) {
			t.Fatalf("packet %d changed", i)
		}
	}
	if _, _, e := r.ReadPacketData(); e != io.EOF {
		t.Fatalf("unexpected trailing data: %v", e)
	}
	if e := WritePackets(t.TempDir(), packets); e == nil {
		t.Fatal("directory accepted as output")
	}
}

func TestWritePropagatesPacketErrors(t *testing.T) {
	raw := make([]byte, 70000)
	p := gopacket.NewPacket(raw, layers.LayerTypeEthernet, gopacket.Default)
	p.Metadata().CaptureInfo = gopacket.CaptureInfo{CaptureLength: len(raw), Length: len(raw)}
	if e := WritePackets(filepath.Join(t.TempDir(), "out.pcap"), []gopacket.Packet{p}); e == nil {
		t.Fatal("oversized packet error swallowed")
	}
}

func TestWriteAnonymizedSIP(t *testing.T) {
	payload := []byte("OPTIONS sip:alice@10.33.44.55 SIP/2.0\r\nContent-Length: 0\r\n\r\n")
	ip := &layers.IPv4{Version: 4, TTL: 64, Protocol: layers.IPProtocolUDP, SrcIP: []byte{10, 33, 44, 55}, DstIP: []byte{10, 33, 44, 56}}
	udp := &layers.UDP{SrcPort: 5060, DstPort: 5060}
	if e := udp.SetNetworkLayerForChecksum(ip); e != nil {
		t.Fatal(e)
	}
	eth := &layers.Ethernet{SrcMAC: []byte{0, 1, 2, 3, 4, 5}, DstMAC: []byte{6, 7, 8, 9, 10, 11}, EthernetType: layers.EthernetTypeIPv4}
	b := gopacket.NewSerializeBuffer()
	if e := gopacket.SerializeLayers(b, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, eth, ip, udp, gopacket.Payload(payload)); e != nil {
		t.Fatal(e)
	}
	p := gopacket.NewPacket(b.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
	p.Metadata().Timestamp = time.Unix(200, 0)
	anonymizer.Process(p, anonymizer.NewConfig())
	anonymizer.UpdateChecksums(p)
	path := filepath.Join(t.TempDir(), "sip.pcap")
	if e := WritePackets(path, []gopacket.Packet{p}); e != nil {
		t.Fatal(e)
	}
	f, e := os.Open(path)
	if e != nil {
		t.Fatal(e)
	}
	defer f.Close()
	r, e := pcapgo.NewReader(f)
	if e != nil {
		t.Fatal(e)
	}
	data, _, e := r.ReadPacketData()
	if e != nil {
		t.Fatal(e)
	}
	got := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.Default)
	if got.ErrorLayer() != nil {
		t.Fatalf("invalid output: %v", got.ErrorLayer())
	}
	if bytes.Contains(data, []byte("10.33.44.55")) {
		t.Fatal("original SIP address leaked")
	}
	if int(binary.BigEndian.Uint16(data[16:18])) != len(data)-14 {
		t.Fatal("incorrect output IP length")
	}
}

func TestReadNanosecondAndBigEndianPCAP(t *testing.T) {
	raw, want := fixture(t, false, 1)
	for _, bigEndian := range []bool{false, true} {
		for _, nano := range []bool{false, true} {
			name := map[bool]string{false: "little", true: "big"}[bigEndian] + map[bool]string{false: "-micro", true: "-nano"}[nano]
			t.Run(name, func(t *testing.T) {
				data := append([]byte(nil), raw...)
				var order binary.ByteOrder = binary.LittleEndian
				if bigEndian {
					order = binary.BigEndian
				}
				magic := uint32(0xa1b2c3d4)
				if nano {
					magic = 0xa1b23c4d
				}
				order.PutUint32(data[:4], magic)
				if bigEndian {
					for _, offset := range []int{4, 6} {
						order.PutUint16(data[offset:offset+2], binary.LittleEndian.Uint16(raw[offset:offset+2]))
					}
					for _, offset := range []int{8, 12, 16, 20, 24, 28, 32, 36} {
						order.PutUint32(data[offset:offset+4], binary.LittleEndian.Uint32(raw[offset:offset+4]))
					}
				}
				fraction := uint32(123456)
				if nano {
					fraction = 123456789
				}
				order.PutUint32(data[28:32], fraction)
				path := filepath.Join(t.TempDir(), name)
				if e := os.WriteFile(path, data, 0600); e != nil {
					t.Fatal(e)
				}
				packets, e := ReadPackets(path)
				if e != nil {
					t.Fatal(e)
				}
				if len(packets) != 1 || !bytes.Equal(packets[0].Data(), want[0]) {
					t.Fatal("packet changed")
				}
				ns := int64(fraction)
				if !nano {
					ns *= 1000
				}
				if !packets[0].Metadata().Timestamp.Equal(time.Unix(100, ns)) {
					t.Fatal("timestamp precision changed")
				}
			})
		}
	}
}
