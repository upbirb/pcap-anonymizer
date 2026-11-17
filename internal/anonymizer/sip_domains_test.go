package anonymizer

import (
	"bytes"
	"strings"
	"testing"
)

func TestSIPURIDomainMapping(t *testing.T) {
	const domain = "pbx.customer.example"
	alias := anonymizeSIPDomain(domain)
	if alias == domain || !strings.HasSuffix(alias, ".invalid") {
		t.Fatalf("invalid replacement %q", alias)
	}
	cases := []struct{ name, input, want string }{
		{"request", "INVITE sip:alice@" + domain + ":5060;transport=udp SIP/2.0\r\n", "INVITE sip:alice@" + alias + ":5060;transport=udp SIP/2.0\r\n"},
		{"sips", "Contact: <sips:alice@PBX.CUSTOMER.EXAMPLE:5061;transport=tls>\r\n", "Contact: <sips:alice@" + alias + ":5061;transport=tls>\r\n"},
		{"root dot", "To: <sip:alice@" + domain + ".>\r\n", "To: <sip:alice@" + alias + ".>\r\n"},
		{"host only", "OPTIONS sip:" + domain + " SIP/2.0\r\n", "OPTIONS sip:" + alias + " SIP/2.0\r\n"},
		{"userinfo", "Contact: <sip:alice:password@" + domain + ">\r\n", "Contact: <sip:alice:password@" + alias + ">\r\n"},
		{"query", "Contact: <sip:alice@" + domain + "?Subject=bob@another.example>\r\n", "Contact: <sip:alice@" + alias + "?Subject=bob@another.example>\r\n"},
		{"parameters", "Route: <sip:" + domain + ";lr;transport=tcp?Subject=hello>\r\n", "Route: <sip:" + alias + ";lr;transport=tcp?Subject=hello>\r\n"},
		{"header extension", "X-Destination: sip:alice@" + domain + "\r\n", "X-Destination: sip:alice@" + alias + "\r\n"},
		{"comma list", "Contact: sip:a@" + domain + ",sip:b@" + domain + "\r\n", "Contact: sip:a@" + alias + ",sip:b@" + alias + "\r\n"},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			got, v4, v6 := anonymizeSIPAddresses(tt.input)
			if got != tt.want || v4 != 0 || v6 != 0 {
				t.Fatalf("got %q (%d,%d), want %q", got, v4, v6, tt.want)
			}
			again, _, _ := anonymizeSIPAddresses(got)
			if again != got {
				t.Fatalf("second pass changed alias: %q", again)
			}
		})
	}
	if anonymizeSIPDomain("other.customer.example") == alias {
		t.Fatal("different domains share an alias")
	}
}

func TestSIPDomainScopeAndInvalidHosts(t *testing.T) {
	for _, input := range []string{
		"Subject: pbx.customer.example\r\n", "Via: SIP/2.0/UDP pbx.customer.example:5060\r\n",
		"Call-ID: opaque@pbx.customer.example\r\n", "c=IN IP4 pbx.customer.example\r\n",
		"Contact: <sip:alice@999.10.20.30>\r\n", "Contact: <sip:alice@-bad.example>\r\n",
		"Contact: <sip:alice@bad..example>\r\n", "Contact: <sip:alice@[pbx.customer.example]>\r\n",
		"Contact: <sip:alice@[2001:db8::1]>\r\n", "Contact: <sip:alice@192.0.2.1:5060>\r\n",
	} {
		got, _, _ := anonymizeSIPAddresses(input)
		if got != input {
			t.Errorf("unexpected change %q -> %q", input, got)
		}
	}
	for _, host := range []string{"", "123.456", "-bad.example", "bad-.example", "bad..example", strings.Repeat("a", 64) + ".example", strings.Repeat("a.", 128) + "example"} {
		if anonymizeSIPDomain(host) != host {
			t.Errorf("invalid hostname was replaced: %q", host)
		}
	}
	for _, host := range []string{"pbx", "xn--e1afmkfd.xn--p1ai"} {
		if anonymizeSIPDomain(host) == host {
			t.Errorf("valid hostname unchanged: %q", host)
		}
	}
}

func TestSIPDomainUDPOutput(t *testing.T) {
	const host = "udp.customer.example"
	p := testPacket(t, false, "udp", []byte("OPTIONS sip:alice@"+host+":5060 SIP/2.0\r\nContent-Length: 0\r\n\r\n"))
	if !Process(p, NewConfig()) {
		t.Fatal("domain-only SIP request was not modified")
	}
	UpdateChecksums(p)
	data := GetModifiedPacketData(p)
	if bytes.Contains(data, []byte(host)) || !bytes.Contains(data, []byte(anonymizeSIPDomain(host)+":5060")) {
		t.Fatal("domain not anonymized in output")
	}
	assertPacketChecksums(t, p)
	for _, count := range []int{0, 1, 100} {
		if len(GetSampleSIPDomainMappings(count)) > count {
			t.Fatal("sample limit exceeded")
		}
	}
	if GetSIPDomainMappingStats() == 0 {
		t.Fatal("domain statistics missing")
	}
}
