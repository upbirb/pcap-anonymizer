package cli

import (
	"fmt"
	"io"
	"log"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/upbirb/pcap-anonymizer/internal/anonymizer"
)

type processingStats struct {
	total, modified, ipv4Modified, ipv6Modified int
}

func processPackets(packets []gopacket.Packet, cfg *anonymizer.Config, out io.Writer, logger *log.Logger) (processingStats, error) {
	var stats processingStats
	for i, packet := range packets {
		stats.total++
		if i > 0 && i%100 == 0 {
			if _, err := fmt.Fprintf(out, "\rProcessed %d/%d packets...", i, len(packets)); err != nil {
				return stats, err
			}
		}
		beforeSrc, beforeDst := getPacketIPs(packet)
		if anonymizer.Process(packet, cfg) {
			stats.modified++
			if packet.Layer(layers.LayerTypeIPv4) != nil {
				stats.ipv4Modified++
			} else if packet.Layer(layers.LayerTypeIPv6) != nil {
				stats.ipv6Modified++
			}
			anonymizer.UpdateChecksums(packet)
		}
		if cfg.VerboseLogging {
			afterSrc, afterDst := getPacketIPs(packet)
			logger.Printf("Packet %d: %s → %s => %s → %s", i, beforeSrc, beforeDst, afterSrc, afterDst)
		}
	}
	_, err := fmt.Fprintln(out)
	return stats, err
}

// getPacketIPs возвращает исходный и целевой IP-адреса пакета
func getPacketIPs(packet gopacket.Packet) (string, string) {
	if net := packet.NetworkLayer(); net != nil {
		switch v := net.(type) {
		case *layers.IPv4:
			return v.SrcIP.String(), v.DstIP.String()
		case *layers.IPv6:
			return v.SrcIP.String(), v.DstIP.String()
		}
	}
	return "", ""
}
