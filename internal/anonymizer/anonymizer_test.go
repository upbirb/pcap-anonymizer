package anonymizer

import (
	"net"
	"strings"
	"testing"
)

func TestIPv4RepresentationsUseSameMapping(t *testing.T) {
	for _, address := range []string{"10.23.45.67", "8.8.4.4"} {
		t.Run(address, func(t *testing.T) {
			short := net.ParseIP(address).To4()
			if !AnonymizeIPv4(short) {
				t.Fatal("IPv4 address was not anonymized")
			}
			for i := 0; i < 2; i++ {
				full := net.ParseIP(address)
				if !AnonymizeIPv4(full) || !full.Equal(short) {
					t.Fatalf("16-byte IPv4 = %s, want %s", full, short)
				}
				if AnonymizeIPv4(full) {
					t.Fatal("documentation address was anonymized again")
				}
			}
		})
	}
}

func TestSIPIPv6UsesNetworkMapping(t *testing.T) {
	for _, address := range []string{"2001:4860:4860::8888", "fe80::1234", "2001:4860::1:2"} {
		t.Run(address, func(t *testing.T) {
			ip := net.ParseIP(address)
			AnonymizeIPv6(ip)
			input := "INVITE sip:alice@[" + address + "]:5060 SIP/2.0\r\n" +
				"X-Forwarded-For: [" + address + "]\r\n\r\n" +
				"c=IN IP6 " + address + "\r\n"
			want := strings.ReplaceAll(input, address, ip.String())
			for i := 0; i < 2; i++ {
				got, _, _, _ := anonymizeSIPContent([]byte(input))
				if string(got) != want {
					t.Fatalf("SIP = %q, want %q", got, want)
				}
			}
		})
	}
}

func TestSIPPreservesDocumentationIPv6(t *testing.T) {
	input := "c=IN IP6 2001:db8::1234\r\n"
	got, _, _, count := anonymizeSIPContent([]byte(input))
	if string(got) != input || count != 0 {
		t.Fatalf("documentation IPv6 changed: %q (count %d)", got, count)
	}
}
