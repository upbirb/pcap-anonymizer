package anonymizer

import (
	"encoding/binary"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// UpdateChecksums обновляет контрольные суммы в пакете
func UpdateChecksums(packet gopacket.Packet) {
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
		if err := ipv4.SerializeTo(buf, opts); err == nil {
			serialized := buf.Bytes()
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
			if err := t.SerializeTo(buf, opts); err == nil {
				serialized := buf.Bytes()
				if len(serialized) >= 16 { // Минимальный размер TCP заголовка
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
			if err := t.SerializeTo(buf, opts); err == nil {
				serialized := buf.Bytes()
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
	if err := icmp.SerializeTo(buf, opts); err == nil {
		serialized := buf.Bytes()
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
	
	if err := icmp.SerializeTo(buf, opts); err == nil {
		icmpBytes := buf.Bytes()
		
		// Вычисляем контрольную сумму для псевдо-заголовка + данных ICMPv6
		fullData := append(pseudoHeader, icmpBytes...)
		checksum := calculateChecksum(fullData)
		
		// Устанавливаем контрольную сумму
		icmp.Checksum = checksum
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
