# PCAP Anonymizer

PCAP Anonymizer is a command-line tool for anonymizing IPv4 and IPv6 addresses in network traffic PCAP files. The program replaces real IP addresses with addresses from ranges designated for documentation purposes, allowing you to safely share captured traffic for analysis, education, or diagnostics.

## Features

- IPv4 and IPv6 address anonymization at the network layer
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
- Addresses already in documentation networks remain unchanged

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
```

### Examples

```bash
# Anonymize a standard PCAP file
./pcap-anon capture.pcap anon-capture.pcap

# Anonymize a compressed PCAP file with verbose output
./pcap-anon capture.pcap.gz anon-capture.pcap -v
```

## Project Structure

```
pcap-anonymizer/
|-------cmd/
|      └── main.go                 # Entry point
├── internal/
│   ├── anonymizer/
│   │   ├── anonymizer.go          # Core anonymization logic
│   │   └── checksums.go           # Checksum updates
│   └── pcap/
│         ├── reader.go            # PCAP file reading
│        └── writer.go             # PCAP file writing
└── go.mod                         # Dependencies
```

## How It Works

1. The program opens the source PCAP file and determines its format
2. For each packet:
   - Analyzes the IP addresses (source and destination)
   - Checks whether they are private or public
   - Replaces addresses according to anonymization rules
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
```

## Limitations

- Anonymization is performed only at the network layer (does not modify IP addresses in payload)
- When exceeding the number of available addresses in the target network (more than 254 for IPv4), counters restart, which may lead to mapping collisions
- Does not preserve subnet information from original IP addresses

## Dependencies

- [google/gopacket](https://github.com/google/gopacket) - for processing network packets and PCAP files

## License

MIT

## Contributing

Contributions are welcome! Please create an issue or pull request to add new features or fix bugs.

## Contact

GitHub: [@upbirb](https://github.com/upbirb)