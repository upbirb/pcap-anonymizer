package cli

import (
	"bytes"
	"errors"
	"flag"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

func cliFixture(t *testing.T, path string) {
	t.Helper()
	f, e := os.Create(path)
	if e != nil {
		t.Fatal(e)
	}
	defer f.Close()
	w := pcapgo.NewWriter(f)
	if e := w.WriteFileHeader(65536, layers.LinkTypeEthernet); e != nil {
		t.Fatal(e)
	}
	for i := 0; i < 102; i++ {
		eth := &layers.Ethernet{SrcMAC: []byte{0, 1, 2, 3, 4, 5}, DstMAC: []byte{6, 7, 8, 9, 10, 11}, EthernetType: layers.EthernetTypeIPv4}
		var ip gopacket.SerializableLayer
		var network gopacket.NetworkLayer
		if i%2 == 0 {
			v := &layers.IPv4{Version: 4, TTL: 64, Protocol: layers.IPProtocolUDP, SrcIP: net.IPv4(10, 11, 12, 13), DstIP: net.IPv4(8, 8, 8, 8)}
			ip = v
			network = v
		} else {
			eth.EthernetType = layers.EthernetTypeIPv6
			v := &layers.IPv6{Version: 6, HopLimit: 64, NextHeader: layers.IPProtocolUDP, SrcIP: net.ParseIP("2001:4860:abcd::1"), DstIP: net.ParseIP("2001:4860:abcd::2")}
			ip = v
			network = v
		}
		udp := &layers.UDP{SrcPort: 5060, DstPort: 5060}
		if e := udp.SetNetworkLayerForChecksum(network); e != nil {
			t.Fatal(e)
		}
		b := gopacket.NewSerializeBuffer()
		if e := gopacket.SerializeLayers(b, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, eth, ip, udp, gopacket.Payload([]byte("OPTIONS sip:alice@10.11.12.13 SIP/2.0\r\nContent-Length: 0\r\n\r\n"))); e != nil {
			t.Fatal(e)
		}
		data := b.Bytes()
		if e := w.WritePacket(gopacket.CaptureInfo{Timestamp: time.Unix(1000, int64(i)*1000000), CaptureLength: len(data), Length: len(data)}, data); e != nil {
			t.Fatal(e)
		}
	}
}

func TestCLIProcessingModes(t *testing.T) {
	for _, mode := range []string{"default", "--no-sip", "--sip-only"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			input, output := filepath.Join(dir, "input.pcap"), filepath.Join(dir, "output.pcap")
			cliFixture(t, input)
			var stdout, stderr bytes.Buffer
			args := []string{input, output, "-v"}
			if mode != "default" {
				args = append(args, mode)
			}
			if err := Run(args, &stdout, &stderr); err != nil {
				t.Fatal(err)
			}
			text := stdout.Bytes()
			if !bytes.Contains(text, []byte("Processing results:")) || !bytes.Contains(text, []byte("Processed 100/102")) {
				t.Fatal("missing statistics or progress")
			}
			f, e := os.Open(output)
			if e != nil {
				t.Fatal(e)
			}
			defer f.Close()
			r, e := pcapgo.NewReader(f)
			if e != nil {
				t.Fatal(e)
			}
			for i := 0; i < 102; i++ {
				data, _, e := r.ReadPacketData()
				if e != nil {
					t.Fatal(e)
				}
				p := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.Default)
				if p.ErrorLayer() != nil {
					t.Fatalf("invalid packet %d: %v", i, p.ErrorLayer())
				}
				src, _ := getPacketIPs(p)
				original := "10.11.12.13"
				if i%2 != 0 {
					original = "2001:4860:abcd::1"
				}
				if (src == original) != (mode == "--sip-only") {
					t.Fatalf("IP flag ignored: %s", src)
				}
				sip := string(p.TransportLayer().LayerPayload())
				if strings.Contains(sip, "alice@10.11.12.13") != (mode == "--no-sip") {
					t.Fatalf("SIP flag ignored: %s", sip)
				}
			}
		})
	}
}

func TestRunErrors(t *testing.T) {
	dir := t.TempDir()
	valid := filepath.Join(dir, "valid.pcap")
	cliFixture(t, valid)
	invalid := filepath.Join(dir, "invalid.pcap")
	if err := os.WriteFile(invalid, []byte("bad"), 0600); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name    string
		args    []string
		message string
	}{
		{"usage", nil, "Usage:"},
		{"missing", []string{filepath.Join(dir, "missing"), filepath.Join(dir, "out")}, "read input"},
		{"invalid", []string{invalid, filepath.Join(dir, "out")}, "read input"},
		{"output", []string{valid, dir}, "write output"},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			err := Run(tt.args, &stdout, &stderr)
			if err == nil || !strings.Contains(err.Error(), tt.message) {
				t.Fatalf("expected %q, got %v", tt.message, err)
			}
			if bytes.Contains(stdout.Bytes(), []byte("Processing results:")) {
				t.Fatal("success report printed after failure")
			}
		})
	}
	var stdout bytes.Buffer
	if err := Run([]string{"--help"}, &stdout, io.Discard); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout.String(), usage) {
		t.Fatal("missing help")
	}
}

func TestParseOptions(t *testing.T) {
	cases := []struct {
		name             string
		args             []string
		ip, sip, verbose bool
		input, output    string
	}{
		{"defaults", []string{"in.pcap", "out.pcap"}, true, true, false, "in.pcap", "out.pcap"},
		{"flags before", []string{"--no-sip", "-v", "in.pcap", "out.pcap"}, true, false, true, "in.pcap", "out.pcap"},
		{"flags after", []string{"in.pcap", "out.pcap", "--sip-only"}, false, true, false, "in.pcap", "out.pcap"},
		{"flags between", []string{"in.pcap", "-v", "out.pcap"}, true, true, true, "in.pcap", "out.pcap"},
		{"explicit false", []string{"-v=false", "in.pcap", "out.pcap"}, true, true, false, "in.pcap", "out.pcap"},
		{"dash paths", []string{"--", "-input.pcap", "-output.pcap"}, true, true, false, "-input.pcap", "-output.pcap"},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			opts, err := parseOptions(tt.args)
			if err != nil {
				t.Fatal(err)
			}
			if opts.input != tt.input || opts.output != tt.output || opts.config.ProcessIP != tt.ip || opts.config.ProcessSIP != tt.sip || opts.config.VerboseLogging != tt.verbose {
				t.Fatalf("unexpected options: %+v", opts)
			}
		})
	}
	for _, args := range [][]string{nil, {"input"}, {"in", "out", "extra"}, {"in", "out", "--typo"}, {"in", "out", "--no-sip", "--sip-only"}, {"in", "out", "-v=bad"}} {
		if _, err := parseOptions(args); err == nil {
			t.Errorf("accepted invalid arguments: %v", args)
		}
	}
	if _, err := parseOptions([]string{"-h"}); !errors.Is(err, flag.ErrHelp) {
		t.Fatalf("expected help: %v", err)
	}
}

type failingWriter struct{}

func (failingWriter) Write(p []byte) (int, error) { return 0, io.ErrClosedPipe }

func TestOutputErrors(t *testing.T) {
	dir := t.TempDir()
	input, output := filepath.Join(dir, "in.pcap"), filepath.Join(dir, "out.pcap")
	cliFixture(t, input)
	if err := Run([]string{input, output}, failingWriter{}, io.Discard); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("output error lost: %v", err)
	}
	if _, err := os.Stat(output); !os.IsNotExist(err) {
		t.Fatal("capture written after progress failure")
	}
	if err := writeReport(failingWriter{}, processingStats{}, time.Second); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("report error lost: %v", err)
	}
	if err := Run([]string{"--help"}, failingWriter{}, io.Discard); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("help error lost: %v", err)
	}
}

func TestGetPacketIPsWithoutNetworkLayer(t *testing.T) {
	p := gopacket.NewPacket(nil, layers.LayerTypeEthernet, gopacket.Default)
	a, b := getPacketIPs(p)
	if a != "" || b != "" {
		t.Fatal("non-IP packet has addresses")
	}
}
