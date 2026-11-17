package anonymizer

import (
	"bytes"
	"log"
	"strings"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func TestDiagnosticConfiguration(t *testing.T) {
	for _, verbose := range []bool{false, true} {
		for _, withLogger := range []bool{false, true} {
			var out bytes.Buffer
			cfg := NewConfig()
			cfg.VerboseLogging = verbose
			if withLogger {
				cfg.Logger = log.New(&out, "", 0)
			}
			p := testPacket(t, false, "udp", []byte("OPTIONS sip:+12025550123@10.40.50.60 SIP/2.0\r\n\r\n"))
			if !Process(p, cfg) {
				t.Fatal("packet not anonymized")
			}
			if (out.Len() > 0) != (verbose && withLogger) {
				t.Errorf("diagnostics do not follow config: verbose=%t logger=%t", verbose, withLogger)
			}
			for _, identity := range []string{"+12025550123", "10.40.50.60", "OPTIONS sip:"} {
				if strings.Contains(out.String(), identity) {
					t.Errorf("diagnostics contain %q", identity)
				}
			}
		}
	}
}

func TestSIPDiagnosticReasons(t *testing.T) {
	cases := []struct {
		name    string
		packet  func(*testing.T) gopacket.Packet
		message string
	}{
		{"no transport", func(t *testing.T) gopacket.Packet {
			return gopacket.NewPacket(nil, layers.LayerTypeIPv4, gopacket.Default)
		}, "SIP: skipped (no transport layer)"},
		{"empty", func(t *testing.T) gopacket.Packet { return testPacket(t, false, "udp", nil) }, "SIP: skipped (empty payload)"},
		{"not SIP", func(t *testing.T) gopacket.Packet { return testPacket(t, false, "udp", []byte("not SIP")) }, "SIP: skipped (payload not recognized as SIP)"},
		{"unchanged", func(t *testing.T) gopacket.Packet {
			return testPacket(t, false, "udp", []byte("OPTIONS sip:service@192.0.2.1 SIP/2.0\r\n\r\n"))
		}, "SIP: content unchanged"},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			var out bytes.Buffer
			cfg := &Config{ProcessSIP: true, VerboseLogging: true, Logger: log.New(&out, "", 0)}
			Process(tt.packet(t), cfg)
			if !strings.Contains(out.String(), tt.message) {
				t.Fatalf("missing diagnostic %q: %s", tt.message, out.String())
			}
		})
	}
}
