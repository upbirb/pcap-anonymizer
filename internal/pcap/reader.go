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

	// Проверяем, является ли файл GZIP
	var reader io.Reader = bufio.NewReader(file)
	if isGzipped, gr := checkGzip(reader); isGzipped {
		reader = gr
	} else {
		// Если не GZIP, переоткрываем файл для повторного чтения
		file.Seek(0, 0)
	}

	// Читаем первые 4 байта для определения формата
	magic := make([]byte, 4)
	if _, err := io.ReadFull(reader, magic); err != nil {
		return nil, fmt.Errorf("error reading magic number: %v", err)
	}

	// Создаем MultiReader для повторного чтения данных
	multiReader := io.MultiReader(bytes.NewReader(magic), reader)

	switch {
	case bytes.Equal(magic, []byte{0xa1, 0xb2, 0xc3, 0xd4}): // PCAP big-endian
		fallthrough
	case bytes.Equal(magic, []byte{0xd4, 0xc3, 0xb2, 0xa1}): // PCAP little-endian
		return readPcap(multiReader)
	case bytes.Equal(magic, []byte{0x0a, 0x0d, 0x0d, 0x0a}): // PCAPNG
		return readPcapng(multiReader)
	default:
		return nil, fmt.Errorf("unsupported file format: unknown magic %x", magic)
	}
}

func checkGzip(r io.Reader) (bool, io.Reader) {
	buf := bufio.NewReader(r)
	peek, err := buf.Peek(2)
	if err != nil || len(peek) < 2 {
		return false, buf
	}

	// Проверяем GZIP magic number (0x1f 0x8b)
	if peek[0] == 0x1f && peek[1] == 0x8b {
		gz, err := gzip.NewReader(buf)
		if err != nil {
			return false, buf
		}
		return true, gz
	}
	return false, buf
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
	for packet := range source.Packets() {
		packets = append(packets, packet)
	}
	return packets, nil
}
