package cli

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"time"

	"github.com/upbirb/pcap-anonymizer/internal/pcap"
)

// Run contains the CLI workflow without terminating the process or replacing
// global input/output streams, allowing callers to handle and test errors.
func Run(args []string, stdout, stderr io.Writer) error {
	opts, err := parseOptions(args)
	if errors.Is(err, flag.ErrHelp) {
		_, err = fmt.Fprintln(stdout, usage)
		return err
	}
	if err != nil {
		return err
	}
	logger := log.New(stderr, "", log.LstdFlags)
	started := time.Now()
	logger.Printf("Reading packets from %s...", opts.input)
	packets, err := pcap.ReadPackets(opts.input)
	if err != nil {
		return fmt.Errorf("read input %q: %w", opts.input, err)
	}
	logger.Printf("Successfully read %d packets", len(packets))
	logger.Println("Processing packets...")
	stats, err := processPackets(packets, &opts.config, stdout, logger)
	if err != nil {
		return fmt.Errorf("write progress: %w", err)
	}
	logger.Printf("Writing anonymized packets to %s...", opts.output)
	if err := pcap.WritePackets(opts.output, packets); err != nil {
		return fmt.Errorf("write output %q: %w", opts.output, err)
	}
	if err := writeReport(stdout, stats, time.Since(started)); err != nil {
		return fmt.Errorf("write report: %w", err)
	}
	return nil
}
