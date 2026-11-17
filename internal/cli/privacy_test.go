package cli

import (
	"bytes"
	"log"
	"path/filepath"
	"strings"
	"testing"
)

func TestOutputDoesNotExposePacketIdentities(t *testing.T) {
	// Capture the default logger too: library logs must not bypass Run's stderr.
	var libraryLogs bytes.Buffer
	previous := log.Writer()
	log.SetOutput(&libraryLogs)
	defer log.SetOutput(previous)
	const phone = "+12025550987"
	const userID = "userabcdef98"
	const domain = "pbx.customer.example"
	payload := []byte("OPTIONS sip:" + phone + "@" + domain + " SIP/2.0\r\nX-Subscriber-ID: " + userID + "\r\nContent-Length: 0\r\n\r\n")
	for _, mode := range []string{"default", "--no-sip", "--sip-only", "-v"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			input, output := filepath.Join(dir, "input.pcap"), filepath.Join(dir, "output.pcap")
			cliFixtureWithPayload(t, input, payload)
			var stdout, stderr bytes.Buffer
			libraryLogs.Reset()
			args := []string{input, output}
			if mode != "default" {
				args = append(args, mode)
			}
			if err := Run(args, &stdout, &stderr); err != nil {
				t.Fatal(err)
			}
			all := stdout.String() + stderr.String() + libraryLogs.String()
			for _, original := range []string{phone, userID, domain, "10.11.12.13", "8.8.8.8", "2001:4860:abcd::1", "2001:4860:abcd::2"} {
				if strings.Contains(all, original) {
					t.Errorf("output exposes original identity %q", original)
				}
			}
			if strings.Contains(all, "mappings:") {
				t.Error("mappings displayed without explicit opt-in")
			}
			if !strings.Contains(stdout.String(), "Processing results:") {
				t.Error("statistics missing")
			}
			if strings.Contains(stderr.String(), "Packet 0:") != (mode == "-v") {
				t.Error("verbose packet diagnostics do not follow -v")
			}
			for _, diagnostic := range []string{"IP: modified=", "SIP: detected protocol=UDP", "SIP: replacements phones=", "payload_bytes="} {
				if strings.Contains(stderr.String(), diagnostic) != (mode == "-v") {
					t.Errorf("diagnostic %q does not follow -v", diagnostic)
				}
			}
			if strings.Contains(libraryLogs.String(), "SIP:") {
				t.Error("SIP diagnostics bypass Run's stderr")
			}
		})
	}
}

func TestMappingOutputRequiresExplicitFlag(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		args := []string{"in.pcap", "out.pcap"}
		if enabled {
			args = append(args, "--show-mappings")
		}
		opts, err := parseOptions(args)
		if err != nil {
			t.Fatal(err)
		}
		if opts.showMappings != enabled {
			t.Fatal("mapping flag ignored")
		}
	}
}

func TestExplicitMappingReport(t *testing.T) {
	dir := t.TempDir()
	input, output := filepath.Join(dir, "input.pcap"), filepath.Join(dir, "output.pcap")
	const phone = "+12025550987"
	const userID = "userabcdef98"
	const domain = "pbx.customer.example"
	cliFixtureWithPayload(t, input, []byte("OPTIONS sip:"+phone+"@"+domain+" SIP/2.0\r\nX-Subscriber-ID: "+userID+"\r\nContent-Length: 0\r\n\r\n"))
	var stdout, stderr bytes.Buffer
	if err := Run([]string{input, output, "--show-mappings"}, &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{"Example IPv4 Private mappings:", "Example IPv4 Public mappings:", "Example IPv6 mappings:", "Example Phone Number mappings:", "Example User ID mappings:", "  " + phone + " -> ", "  " + userID + " -> ", "Example URI Domain mappings:", "  " + domain + " -> "} {
		if !strings.Contains(stdout.String(), value) {
			t.Errorf("explicit report is missing %q", value)
		}
	}
	if strings.Contains(stderr.String(), phone) || strings.Contains(stderr.String(), userID) || strings.Contains(stderr.String(), domain) {
		t.Error("mapping identities leaked to diagnostics")
	}
}
