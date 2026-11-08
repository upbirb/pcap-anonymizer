package pcap

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"os"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcapgo"
)

func ReadPackets(filename string) ([]gopacket.Packet, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("error opening file: %v", err)
	}
	defer file.Close()

	buffered := bufio.NewReader(file)
	var reader io.Reader = buffered
	if magic, _ := buffered.Peek(2); bytes.Equal(magic, []byte{0x1f, 0x8b}) {
		gz, err := gzip.NewReader(buffered)
		if err != nil {
			return nil, fmt.Errorf("gzip read error: %w", err)
		}
		defer gz.Close()
		reader = gz
	}

	// Читаем первые 4 байта для определения формата
	magic := make([]byte, 4)
	if _, err := io.ReadFull(reader, magic); err != nil {
		return nil, fmt.Errorf("error reading magic number: %v", err)
	}

	// Создаем MultiReader для повторного чтения данных
	multiReader := io.MultiReader(bytes.NewReader(magic), reader)

	switch {
	case bytes.Equal(magic, []byte{0xa1, 0xb2, 0xc3, 0xd4}), bytes.Equal(magic, []byte{0xa1, 0xb2, 0x3c, 0x4d}): // PCAP big-endian
		fallthrough
	case bytes.Equal(magic, []byte{0xd4, 0xc3, 0xb2, 0xa1}), bytes.Equal(magic, []byte{0x4d, 0x3c, 0xb2, 0xa1}): // PCAP little-endian
		return readPcap(multiReader)
	case bytes.Equal(magic, []byte{0x0a, 0x0d, 0x0d, 0x0a}): // PCAPNG
		return readPcapng(multiReader)
	default:
		return nil, fmt.Errorf("unsupported file format: unknown magic %x", magic)
	}
}

func readPcap(reader io.Reader) ([]gopacket.Packet, error) {
	r, err := pcapgo.NewReader(reader)
	if err != nil {
		return nil, fmt.Errorf("pcap read error: %v", err)
	}
	source := gopacket.NewPacketSource(r, r.LinkType())
	return readPacketsFromSource(source)
}

func readPcapng(reader io.Reader) ([]gopacket.Packet, error) {
	r, err := pcapgo.NewNgReader(reader, pcapgo.DefaultNgReaderOptions)
	if err != nil {
		return nil, fmt.Errorf("pcapng read error: %v", err)
	}
	source := gopacket.NewPacketSource(r, r.LinkType())
	return readPacketsFromSource(source)
}

func readPacketsFromSource(source *gopacket.PacketSource) ([]gopacket.Packet, error) {
	var packets []gopacket.Packet
	for {
		packet, err := source.NextPacket()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("packet read error: %w", err)
		}
		packets = append(packets, packet)
	}
	return packets, nil
}
