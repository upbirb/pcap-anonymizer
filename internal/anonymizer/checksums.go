package anonymizer

import (
	"encoding/binary"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// UpdateChecksums обновляет контрольные суммы пакета после изменений IP-адресов
func UpdateChecksums(packet gopacket.Packet) {
	// SIP replacements can change payload size. Decode the updated bytes only
	// after fixing the IP length, otherwise the decoder may truncate the payload.
	if data := GetModifiedPacketData(packet); data != nil {
		offset := 0
		for _, layer := range packet.Layers() {
			if layer == packet.NetworkLayer() {
				break
			}
			offset += len(layer.LayerContents())
		}
		if len(data) <= offset {
			return
		}
		switch data[offset] >> 4 {
		case 4:
			if len(data) < offset+20 {
				return
			}
			binary.BigEndian.PutUint16(data[offset+2:offset+4], uint16(len(data)-offset))
		case 6:
			if len(data) < offset+40 {
				return
			}
			binary.BigEndian.PutUint16(data[offset+4:offset+6], uint16(len(data)-offset-40))
		default:
			return
		}
		updated := gopacket.NewPacket(data, packet.Layers()[0].LayerType(), gopacket.Default)
		UpdateChecksums(updated)
		copy(data, updated.Data())
		return
	}
	networkLayer := packet.NetworkLayer()
	if networkLayer == nil {
		return
	}

	// Обновляем контрольные суммы для транспортного уровня
	updateTransportChecksums(packet, networkLayer)

	// Обновляем контрольные суммы для ICMP
	updateICMPChecksums(packet, networkLayer)

	// Обновляем IP-заголовок для IPv4
	if ipv4, ok := networkLayer.(*layers.IPv4); ok {
		// Пересчитываем контрольную сумму IP-заголовка
		ipv4.Checksum = 0
		buf := gopacket.NewSerializeBuffer()
		opts := gopacket.SerializeOptions{
			ComputeChecksums: true,
			FixLengths:       true,
		}
		if err := gopacket.SerializeLayers(buf, opts, ipv4, gopacket.Payload(ipv4.Payload)); err == nil {
			serialized := buf.Bytes()
			copy(ipv4.Contents, serialized[:len(ipv4.Contents)])
			if len(serialized) >= 20 { // Минимальный размер IPv4 заголовка
				ipv4.Checksum = binary.BigEndian.Uint16(serialized[10:12])
			}
		}
	}
}

func updateTransportChecksums(packet gopacket.Packet, networkLayer gopacket.NetworkLayer) {
	if transport := packet.TransportLayer(); transport != nil {
		switch t := transport.(type) {
		case *layers.TCP:
			// Обнуляем контрольную сумму перед её вычислением
			t.Checksum = 0
			t.SetNetworkLayerForChecksum(networkLayer)

			// Сериализуем для вычисления контрольной суммы
			buf := gopacket.NewSerializeBuffer()
			opts := gopacket.SerializeOptions{
				ComputeChecksums: true,
				FixLengths:       true,
			}
			if err := gopacket.SerializeLayers(buf, opts, t, gopacket.Payload(t.Payload)); err == nil {
				serialized := buf.Bytes()
				copy(t.Contents, serialized[:len(t.Contents)])
				if len(serialized) >= 18 { // Минимальный размер TCP заголовка
					t.Checksum = binary.BigEndian.Uint16(serialized[16:18])
				}
			}

		case *layers.UDP:
			// Обнуляем контрольную сумму перед её вычислением
			t.Checksum = 0
			t.SetNetworkLayerForChecksum(networkLayer)

			// Сериализуем для вычисления контрольной суммы
			buf := gopacket.NewSerializeBuffer()
			opts := gopacket.SerializeOptions{
				ComputeChecksums: true,
				FixLengths:       true,
			}
			if err := gopacket.SerializeLayers(buf, opts, t, gopacket.Payload(t.Payload)); err == nil {
				serialized := buf.Bytes()
				copy(t.Contents, serialized[:len(t.Contents)])
				if len(serialized) >= 8 { // Размер UDP заголовка
					t.Checksum = binary.BigEndian.Uint16(serialized[6:8])
				}
			}
		}
	}
}

func updateICMPChecksums(packet gopacket.Packet, networkLayer gopacket.NetworkLayer) {
	// Обработка ICMPv4
	if icmpLayer := packet.Layer(layers.LayerTypeICMPv4); icmpLayer != nil {
		if icmp4, ok := icmpLayer.(*layers.ICMPv4); ok {
			updateICMPv4Checksum(icmp4)
		}
	}

	// Обработка ICMPv6
	if icmpLayer := packet.Layer(layers.LayerTypeICMPv6); icmpLayer != nil {
		if icmp6, ok := icmpLayer.(*layers.ICMPv6); ok {
			if ipv6, ok := networkLayer.(*layers.IPv6); ok {
				updateICMPv6Checksum(icmp6, ipv6)
			}
		}
	}
}

func updateICMPv4Checksum(icmp *layers.ICMPv4) {
	// Обнуляем контрольную сумму перед её вычислением
	icmp.Checksum = 0

	// Сериализуем для вычисления контрольной суммы
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}
	if err := gopacket.SerializeLayers(buf, opts, icmp, gopacket.Payload(icmp.Payload)); err == nil {
		serialized := buf.Bytes()
		copy(icmp.Contents, serialized[:len(icmp.Contents)])
		if len(serialized) >= 4 { // Минимальный размер ICMP заголовка
			icmp.Checksum = binary.BigEndian.Uint16(serialized[2:4])
		}
	}
}

func updateICMPv6Checksum(icmp *layers.ICMPv6, ipv6 *layers.IPv6) {
	// Обнуляем контрольную сумму
	icmp.Checksum = 0

	// Создаем псевдо-заголовок IPv6 для вычисления контрольной суммы
	var pseudoHeader []byte
	pseudoHeader = append(pseudoHeader, ipv6.SrcIP...)
	pseudoHeader = append(pseudoHeader, ipv6.DstIP...)

	// Длина пакета ICMPv6
	length := make([]byte, 4)
	icmpLength := uint32(len(icmp.Contents) + len(icmp.Payload))
	binary.BigEndian.PutUint32(length, icmpLength)
	pseudoHeader = append(pseudoHeader, length...)

	// Нули + следующий заголовок (ICMPv6 = 58)
	pseudoHeader = append(pseudoHeader, []byte{0, 0, 0, 58}...)

	// Сериализуем ICMPv6 пакет
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		ComputeChecksums: false, // Не вычислять контрольную сумму при сериализации
		FixLengths:       true,
	}

	if err := gopacket.SerializeLayers(buf, opts, icmp, gopacket.Payload(icmp.Payload)); err == nil {
		icmpBytes := buf.Bytes()

		// Вычисляем контрольную сумму для псевдо-заголовка + данных ICMPv6
		fullData := append(pseudoHeader, icmpBytes...)
		checksum := calculateChecksum(fullData)

		// Устанавливаем контрольную сумму
		icmp.Checksum = checksum
		binary.BigEndian.PutUint16(icmp.Contents[2:4], checksum)
	}
}

// calculateChecksum вычисляет 16-битную контрольную сумму для данных
func calculateChecksum(data []byte) uint16 {
	var sum uint32

	// Суммируем 16-битные слова
	for i := 0; i < len(data)-1; i += 2 {
		sum += uint32(data[i])<<8 | uint32(data[i+1])
	}

	// Если длина нечетная, добавляем последний байт
	if len(data)%2 == 1 {
		sum += uint32(data[len(data)-1]) << 8
	}

	// Складываем перенос с результатом
	for sum > 0xffff {
		sum = (sum & 0xffff) + (sum >> 16)
	}

	// Инвертируем биты
	return ^uint16(sum)
}
