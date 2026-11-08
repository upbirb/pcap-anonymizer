package anonymizer

import (
	"net"
	"strings"
	"testing"
)

func TestSIPAndSDPAddressFields(t *testing.T) {
	const v4 = "10.78.90.12"
	const v6 = "2001:4860:0:200f::b"
	ip4, ip6 := net.ParseIP(v4), net.ParseIP(v6)
	AnonymizeIPv4(ip4)
	AnonymizeIPv6(ip6)
	tests := []struct {
		name, input string
		four, six   int
	}{
		{"request", "INVITE sips:alice@[" + v6 + "]:5061;transport=tls SIP/2.0\r\n", 0, 1},
		{"contacts", "Contact: <sip:" + v4 + ":5060>, <sip:alice@[" + v6 + "]>\r\n", 1, 1},
		{"via", "Via: SIP/2.0/UDP " + v4 + ":5060;received=" + v4 + ", SIP/2.0/TCP [" + v6 + "]:5070\r\n", 2, 1},
		{"compact via", "v: SIP/2.0/UDP [" + v6 + "]:5060;maddr=" + v4 + "\r\n", 1, 1},
		{"call id", "Call-ID: opaque@[" + v6 + "]:5060\r\n", 0, 1},
		{"forwarded", "X-Forwarded-For: " + v4 + ", [" + v6 + "]\r\n", 1, 1},
		{"origin", "o=- 123 1 IN IP6 " + v6 + "\r\n", 0, 1},
		{"connection", "c=IN IP4 " + v4 + "/127/2\r\n", 1, 0},
		{"rtcp", "a=rtcp:26703 IN IP4 " + v4 + "\r\n", 1, 0},
		{"ice", "a=candidate:1 1 UDP 123 " + v4 + " 5000 typ srflx raddr " + v4 + " rport 4000\r\n", 2, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			want := strings.ReplaceAll(strings.ReplaceAll(tt.input, v4, ip4.String()), v6, ip6.String())
			got, four, six := anonymizeSIPAddresses(tt.input)
			if got != want || four != tt.four || six != tt.six {
				t.Fatalf("got %q (%d,%d), want %q (%d,%d)", got, four, six, want, tt.four, tt.six)
			}
			again, four, six := anonymizeSIPAddresses(got)
			if again != got || four != 0 || six != 0 {
				t.Fatalf("second pass changed addresses: %q", again)
			}
		})
	}
}

func TestSIPAddressesPreserveNonAddressValues(t *testing.T) {
	for _, input := range []string{
		"Contact: <sip:alice@host.example:5060>\r\n",
		"Contact: <sip:alice@[2001:db8::1234]:5060>\r\n",
		"Contact: <sip:alice@[2001:4860::xyz]:5060>\r\n",
		"Contact: <sip:alice@999.10.20.30:5060>\r\n",
		"X-Account-Info: invoice-10.78.90.12\r\n",
		"X-Debug: not-an-ip-2001:4860::1234\r\n",
		"a=fmtp:101 0-15\r\n",
		"Subject: 10.78.90.12\r\n",
	} {
		got, four, six := anonymizeSIPAddresses(input)
		if got != input || four != 0 || six != 0 {
			t.Errorf("unexpected change %q => %q", input, got)
		}
	}
}

func TestSIPIPv6SpellingsShareMapping(t *testing.T) {
	address := net.ParseIP("2001:4860:0:200f::b")
	AnonymizeIPv6(address)
	for _, literal := range []string{"2001:4860:0:200f::b", "2001:4860:0000:200F:0000:0000:0000:000B"} {
		got, _, _ := anonymizeSIPAddresses("c=IN IP6 " + literal + "\r\n")
		if got != "c=IN IP6 "+address.String()+"\r\n" {
			t.Errorf("different mapping for %s: %q", literal, got)
		}
	}
}

func TestSIPMappingCanBeCreatedBeforeNetworkMapping(t *testing.T) {
	for _, literal := range []string{"10.67.89.123", "2001:4860:1234::abcd"} {
		result, four, six := anonymizeSIPAddresses("X-Real-IP: " + literal + "\r\n")
		if four+six != 1 {
			t.Fatalf("address was not replaced: %q", result)
		}
		ip := net.ParseIP(literal)
		if ip.To4() != nil {
			AnonymizeIPv4(ip)
		} else {
			AnonymizeIPv6(ip)
		}
		if result != "X-Real-IP: "+ip.String()+"\r\n" {
			t.Fatalf("SIP/network mappings differ: %q vs %s", result, ip)
		}
	}
}
