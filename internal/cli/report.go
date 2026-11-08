package cli

import (
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/upbirb/pcap-anonymizer/internal/anonymizer"
)

func writeReport(out io.Writer, stats processingStats, duration time.Duration) error {
	var text strings.Builder
	// Получаем статистику
	privateCount, publicCount, ipv6Count := anonymizer.GetIPMappingStats()
	sipDetected, sipModified, sipPhones, sipIPv4, sipIPv6, sipErrors, userIDs := anonymizer.GetSIPStatsData()

	// Получаем примеры анонимизированных данных
	privateMap, publicMap, ipv6Map := anonymizer.GetSampleIPMappings(5)
	phoneMap := anonymizer.GetSampleSIPPhoneMappings(5)
	userIDMap := anonymizer.GetSampleUserIDMappings(5)

	// Выводим общую статистику

	fmt.Fprintf(&text, `
	Processing results:
	- Total packets:      %d
	- Modified packets:   %d
	- IPv4 modified:      %d
	- IPv6 modified:      %d
	- Processing time:    %s
	
	IP Anonymization:
	- Private IPv4:       %d unique addresses
	- Public IPv4:        %d unique addresses
	- IPv6:               %d unique addresses
	
	SIP Anonymization:
	- Detected:           %d SIP packets
	- Modified:           %d SIP packets
	- Phone numbers:      %d found and anonymized
	- IPv4 in content:    %d found and anonymized
	- IPv6 in content:    %d found and anonymized
	- User IDs:           %d found and anonymized
	- Serialization errors: %d
	`, stats.total, stats.modified, stats.ipv4Modified, stats.ipv6Modified,
		duration, privateCount, publicCount, ipv6Count,
		sipDetected, sipModified, sipPhones, sipIPv4, sipIPv6, userIDs, sipErrors)

	// Выводим примеры анонимизированных IP-адресов
	fmt.Fprintln(&text, "\nExample IPv4 Private mappings:")
	for original, anonymized := range privateMap {
		fmt.Fprintf(&text, "  %s -> %s\n", original, anonymized)
	}

	fmt.Fprintln(&text, "\nExample IPv4 Public mappings:")
	for original, anonymized := range publicMap {
		fmt.Fprintf(&text, "  %s -> %s\n", original, anonymized)
	}

	fmt.Fprintln(&text, "\nExample IPv6 mappings:")
	for original, anonymized := range ipv6Map {
		fmt.Fprintf(&text, "  %s -> %s\n", original, anonymized)
	}

	// Выводим примеры анонимизированных телефонных номеров
	fmt.Fprintln(&text, "\nExample Phone Number mappings:")
	for original, anonymized := range phoneMap {
		fmt.Fprintf(&text, "  %s -> %s\n", original, anonymized)
	}

	// Выводим примеры анонимизированных идентификаторов пользователей
	fmt.Fprintln(&text, "\nExample User ID mappings:")
	for original, anonymized := range userIDMap {
		fmt.Fprintf(&text, "  %s -> %s\n", original, anonymized)
	}

	_, err := io.WriteString(out, text.String())
	return err
}
