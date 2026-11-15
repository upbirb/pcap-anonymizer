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
		modified := anonymizer.Process(packet, cfg)
		if modified {
			stats.modified++
			if packet.Layer(layers.LayerTypeIPv4) != nil {
				stats.ipv4Modified++
			} else if packet.Layer(layers.LayerTypeIPv6) != nil {
				stats.ipv6Modified++
			}
			anonymizer.UpdateChecksums(packet)
		}
		if cfg.VerboseLogging {
			logger.Printf("Packet %d: modified=%t", i, modified)
		}
	}
	_, err := fmt.Fprintln(out)
	return stats, err
}
