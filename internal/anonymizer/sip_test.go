package anonymizer

import (
	"bytes"
	"fmt"
	"net"
	"strings"
	"testing"
)

func TestPhoneMappingStableWithPrefix(t *testing.T) {
	for _, number := range []string{"+12025550123", "12025550123"} {
		first := getAnonymizedPhoneNumber(number)
		if first == number || len(first) != len(number) || strings.HasPrefix(first, "+") != strings.HasPrefix(number, "+") {
			t.Fatalf("invalid replacement %s => %s", number, first)
		}
		for i := 0; i < 3; i++ {
			if got := getAnonymizedPhoneNumber(number); got != first {
				t.Fatalf("unstable phone: %s != %s", got, first)
			}
		}
	}
}

func TestSIPDisplayAndURIPhoneConsistency(t *testing.T) {
	const number = "+12025550987"
	input := "From: \"" + number + "\" <sip:" + number + "@example.test>\r\n"
	got, count, _, _ := anonymizeSIPContent([]byte(input))
	replacement := getAnonymizedPhoneNumber(number)
	want := strings.ReplaceAll(input, number, replacement)
	if string(got) != want || count != 2 {
		t.Fatalf("got %q count %d, want %q count 2", got, count, want)
	}
}

func TestSIPIdentifiersAndStatistics(t *testing.T) {
	for _, id := range []string{"user1234", "account1234", "subscriber1234", "customer1234", "id123456"} {
		first := anonymizeUserIDs(id)
		if first == id {
			t.Errorf("identifier unchanged: %s", id)
		}
		if second := anonymizeUserIDs(id); second != first {
			t.Errorf("unstable identifier: %s", id)
		}
	}
	input := "X-Account-Info: 12025550999 user5678\r\n"
	got, count, _, _ := anonymizeSIPContent([]byte(input))
	if count != 1 || bytes.Contains(got, []byte("12025550999")) || bytes.Contains(got, []byte("user5678")) {
		t.Fatalf("extension header not anonymized: %q", got)
	}
	if GetSIPPhoneMappingStats() == 0 {
		t.Fatal("missing phone statistics")
	}
	for _, n := range []int{0, 1, 100} {
		if len(GetSampleSIPPhoneMappings(n)) > n || len(GetSampleUserIDMappings(n)) > n {
			t.Fatal("sample count exceeded")
		}
	}
	_, _, _, _, _, _, users := GetSIPStatsData()
	if users < 5 {
		t.Fatal("missing user statistics")
	}
}

func TestSIPDetection(t *testing.T) {
	for _, method := range []string{"INVITE", "ACK", "BYE", "CANCEL", "OPTIONS", "REGISTER", "REFER", "NOTIFY", "SUBSCRIBE", "MESSAGE", "INFO", "SIP/2.0"} {
		if !isSIPPacket([]byte(method + " something")) {
			t.Errorf("not detected: %s", method)
		}
	}
	for _, payload := range []string{"", "abc", "GET / HTTP/1.1", "random payload"} {
		if isSIPPacket([]byte(payload)) {
			t.Errorf("false detection: %s", payload)
		}
	}
}

func TestSIPPacketCacheUsesPacketIdentity(t *testing.T) {
	first := testPacket(t, false, "udp", []byte("OPTIONS sip:alice@10.90.80.70 SIP/2.0\r\n\r\n"))
	second := testPacket(t, false, "udp", []byte("OPTIONS sip:bob@10.90.80.71 SIP/2.0\r\n\r\n"))
	second.Metadata().Timestamp = first.Metadata().Timestamp
	if !ProcessSIPPacket(first) || !ProcessSIPPacket(second) {
		t.Fatal("SIP not processed")
	}
	if !bytes.Contains(GetModifiedPacketData(first), []byte("alice")) || !bytes.Contains(GetModifiedPacketData(second), []byte("bob")) {
		t.Fatal("same timestamp caused packet replacement")
	}
}

func TestSIPContentLengthAfterReplacement(t *testing.T) {
	for _, header := range []string{"Content-Length", "l"} {
		body := "c=IN IP6 2001:4860:abcd:1234::1\r\n"
		input := fmt.Sprintf("OPTIONS sip:example.test SIP/2.0\r\n%s: %d\r\n\r\n%s", header, len(body), body)
		got, _, _, _ := anonymizeSIPContent([]byte(input))
		head, result, _ := strings.Cut(string(got), "\r\n\r\n")
		if !strings.Contains(head, fmt.Sprintf("%s: %d", header, len(result))) {
			t.Fatalf("incorrect body length: %q", got)
		}
	}
}

func TestProcessConfiguration(t *testing.T) {
	cfg := NewConfig()
	if !cfg.ProcessIP || !cfg.ProcessSIP || cfg.VerboseLogging {
		t.Fatal("unexpected defaults")
	}
	for _, ipEnabled := range []bool{false, true} {
		for _, sipEnabled := range []bool{false, true} {
			p := testPacket(t, false, "udp", []byte("OPTIONS sip:alice@10.40.50.60 SIP/2.0\r\n\r\n"))
			before := p.NetworkLayer().NetworkFlow().Src().String()
			changed := Process(p, &Config{ProcessIP: ipEnabled, ProcessSIP: sipEnabled})
			if changed != (ipEnabled || sipEnabled) {
				t.Fatal("incorrect modified flag")
			}
			if (p.NetworkLayer().NetworkFlow().Src().String() != before) != ipEnabled {
				t.Fatal("IP processing configuration ignored")
			}
			if (GetModifiedPacketData(p) != nil) != sipEnabled {
				t.Fatal("SIP processing configuration ignored")
			}
		}
	}
	for _, proto := range []string{"udp", "tcp", "icmp"} {
		p := testPacket(t, false, proto, []byte("not SIP"))
		if ProcessSIPPacket(p) {
			t.Fatal("non-SIP packet modified")
		}
	}
	p := testPacket(t, false, "udp", nil)
	if ProcessSIPPacket(p) {
		t.Fatal("empty payload modified")
	}
}

func TestAddressClassificationAndStats(t *testing.T) {
	AnonymizeIPv4(net.ParseIP("10.91.92.93"))
	AnonymizeIPv4(net.ParseIP("9.9.9.9"))
	AnonymizeIPv6(net.ParseIP("2001:4860:5678::1"))
	for _, ip := range []string{"10.0.0.1", "172.16.0.1", "192.168.1.1", "127.0.0.1", "169.254.1.1", "0.0.0.0"} {
		if !IsPrivateIPv4(net.ParseIP(ip)) {
			t.Errorf("not private: %s", ip)
		}
	}
	if IsPrivateIPv4(net.ParseIP("8.8.8.8")) {
		t.Fatal("public classified as private")
	}
	for _, ip := range []string{"192.0.2.1", "198.51.100.1", "203.0.113.1"} {
		v := net.ParseIP(ip)
		if !IsDocumentationIPv4(v) || AnonymizeIPv4(v) {
			t.Errorf("documentation address changed: %s", ip)
		}
	}
	if AnonymizeIPv4(nil) || AnonymizeIPv4(net.ParseIP("2001:4860::1")) {
		t.Fatal("invalid IPv4 accepted")
	}
	a, b, c := GetIPMappingStats()
	if a == 0 || b == 0 || c == 0 {
		t.Fatal("missing IP statistics")
	}
	for _, n := range []int{0, 1, 100} {
		a, b, c := GetSampleIPMappings(n)
		if len(a) > n || len(b) > n || len(c) > n {
			t.Fatal("sample count exceeded")
		}
	}
}
