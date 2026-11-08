package cli

import (
	"flag"
	"fmt"
	"io"
	"strings"

	"github.com/upbirb/pcap-anonymizer/internal/anonymizer"
)

const usage = "Usage: pcap-anon <input.pcap> <output.pcap> [-v] [--no-sip] [--sip-only]"

type options struct {
	input, output string
	config        anonymizer.Config
}

func parseOptions(args []string) (options, error) {
	opts := options{config: *anonymizer.NewConfig()}
	var noSIP, sipOnly bool
	flags := flag.NewFlagSet("pcap-anon", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.BoolVar(&opts.config.VerboseLogging, "v", false, "enable verbose logging")
	flags.BoolVar(&noSIP, "no-sip", false, "disable SIP anonymization")
	flags.BoolVar(&sipOnly, "sip-only", false, "only anonymize SIP content")

	// flag stops at the first positional argument. Collect flags first to keep
	// supporting the documented syntax with flags after input/output paths.
	var flagArgs, paths []string
	positionalOnly := false
	for _, arg := range args {
		if !positionalOnly && arg == "--" {
			positionalOnly = true
			continue
		}
		if !positionalOnly && strings.HasPrefix(arg, "-") && arg != "-" {
			flagArgs = append(flagArgs, arg)
		} else {
			paths = append(paths, arg)
		}
	}
	if err := flags.Parse(flagArgs); err != nil {
		return opts, err
	}
	if len(paths) != 2 {
		return opts, fmt.Errorf("expected input and output paths\n%s", usage)
	}
	if noSIP && sipOnly {
		return opts, fmt.Errorf("--no-sip and --sip-only cannot be used together")
	}
	opts.input, opts.output = paths[0], paths[1]
	opts.config.ProcessIP = !sipOnly
	opts.config.ProcessSIP = !noSIP
	return opts, nil
}
