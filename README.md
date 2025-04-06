# PCAP Anonymizer

PCAP Anonymizer is a command-line tool for anonymizing IPv4/IPv6 addresses and sensitive data in PCAP network traffic files. It preserves packet structure while replacing sensitive information with documentation addresses, allowing you to safely share captured traffic for analysis, education, or diagnostics.

## Features

- Anonymization of IPv4 and IPv6 addresses at the network layer
- Anonymization of telephone numbers and IP addresses in SIP (Session Initiation Protocol) packets
- Support for PCAP and PCAPNG formats
- Support for GZIP compressed files
- Consistent address replacement (the same address is always replaced with the same anonymized address)
- Automatic checksum updates for IP, TCP, UDP, and ICMP headers
- Detailed anonymization statistics
- Verbose mode for debugging

## Anonymization Rules

- Private IPv4 addresses (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, etc.) are replaced with addresses from the **192.0.2.0/24** network
- Public IPv4 addresses are replaced with addresses from the **203.0.113.0/24** network
- IPv6 addresses are replaced with addresses from the **2001:db8::/32** network
- Phone numbers in SIP messages are replaced with numbers starting with **555**
- IP addresses inside SIP message contents are anonymized using the same mapping as at the network layer

## Installation

### Prerequisites

- Go 1.18 or newer

### Building from Source

```bash
# Clone the repository
git clone https://github.com/upbirb/pcap-anonymizer.git
cd pcap-anonymizer

# Build the project
go build -o pcap-anon ./cmd/main.go
```

## Usage

```bash
# Basic usage
./pcap-anon <input.pcap> <output.pcap>

# With verbose output enabled
./pcap-anon <input.pcap> <output.pcap> -v

# Disable SIP anonymization
./pcap-anon <input.pcap> <output.pcap> --no-sip

# Only anonymize SIP content (leave IP layers unchanged)
./pcap-anon <input.pcap> <output.pcap> --sip-only
```

### Examples

```bash
# Anonymize a standard PCAP file
./pcap-anon capture.pcap anon-capture.pcap

# Anonymize a compressed PCAP file with verbose output
./pcap-anon capture.pcap.gz anon-capture.pcap -v

# Anonymize only IP headers, not SIP content
./pcap-anon sip-traffic.pcap ip-only.pcap --no-sip

# Anonymize only SIP content, not IP headers
./pcap-anon sip-traffic.pcap sip-only.pcap --sip-only
```

## Project Structure

```
pcap-anonymizer/
|-------cmd/
|      └── main.go                 # Entry point
├── internal/
│   ├── anonymizer/
│   │   ├── anonymizer.go          # IP anonymization logic
│   │   ├── checksums.go           # Checksum updates
│   │   └── sip.go                 # SIP content anonymization
│   └── pcap/
│         ├── reader.go            # PCAP file reading
│        └── writer.go             # PCAP file writing
└── go.mod                         # Dependencies
```

## How It Works

1. The program opens the source PCAP file and determines its format
2. For each packet:
   - Analyzes the IP addresses (source and destination) and anonymizes them if configured
   - Detects SIP packets and anonymizes telephone numbers and IP addresses in their content if configured
   - Updates checksums in protocol headers
3. Writes the modified packets to the output file
4. Displays statistics about the performed anonymization

## Example Output

```
Processing results:
- Total packets:      1500
- Modified packets:   1423
- IPv4 modified:      1390
- IPv6 modified:      33
- Processing time:    350ms

IP Anonymization:
- Private IPv4:       15 unique addresses
- Public IPv4:        45 unique addresses
- IPv6:               12 unique addresses

SIP Anonymization:
- Detected:           128 SIP packets
- Modified:           128 SIP packets
- Phone numbers:      256 found and anonymized
- IPv4 in content:    89 found and anonymized
- IPv6 in content:    42 found and anonymized
- Serialization errors: 0

Example IPv4 Private mappings:
  192.168.1.1 -> 192.0.2.1
  10.0.0.1 -> 192.0.2.2
  172.16.0.10 -> 192.0.2.3

Example IPv4 Public mappings:
  8.8.8.8 -> 203.0.113.1
  1.1.1.1 -> 203.0.113.2
  104.26.10.229 -> 203.0.113.3

Example IPv6 mappings:
  2a00:1450:4001:816::200e -> 2001:db8::1
  2606:4700:4700::1111 -> 2001:db8::2
  2606:4700:4700::1001 -> 2001:db8::3

Example Phone Number mappings:
  +79261234567 -> +5550000001
  4959876543 -> 5550000002
  12125551212 -> 5550000003
```

## SIP Anonymization Details

The tool anonymizes the following elements in SIP (Session Initiation Protocol) packets:

- Telephone numbers in SIP URIs (e.g., `sip:+79261234567@domain.com`)
- Telephone numbers in display names and headers
- IPv4 addresses in SIP message content
- IPv6 addresses in SIP message content, including those in Request-URI

The anonymization preserves the format of the original data:
- Phone numbers keep their original length and +/- prefix
- IP addresses are replaced consistently using the same mapping as at the network layer

## Limitations

- Anonymization is performed only at the network layer and in SIP protocol content
- When exceeding the number of available addresses in the target network (more than 254 for IPv4), counters restart, which may lead to mapping collisions
- Does not preserve subnet information from original IP addresses
- Does not support encrypted SIP traffic or other VoIP protocols (only plain SIP)

## Dependencies

- [google/gopacket](https://github.com/google/gopacket) - for processing network packets and PCAP files

## License

MIT

## Contributing

Contributions are welcome! Please create an issue or pull request to add new features or fix bugs.

## Contact

GitHub: [@upbirb](https://github.com/upbirb)