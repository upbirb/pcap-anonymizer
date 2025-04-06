package pcap

import (
	"log"
	"os"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

func WritePackets(filename string, packets []gopacket.Packet) error {
	if len(packets) == 0 {
		return nil
	}

	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := pcapgo.NewWriter(file)
	linkType := getLinkType(packets[0])

	if err := writer.WriteFileHeader(65536, linkType); err != nil {
		return err
	}

	// Счетчики для отладки
	total := 0
	dropped := 0

	for i, packet := range packets {
		total++
		
		// Сохраняем информацию о времени захвата
		ci := packet.Metadata().CaptureInfo
		
		// Используем метод сериализации пакета
		buf := gopacket.NewSerializeBuffer()
		opts := gopacket.SerializeOptions{
			FixLengths:       true,
			ComputeChecksums: true,
		}
		
		// Сериализуем пакет
		if err := gopacket.SerializePacket(buf, opts, packet); err != nil {
			log.Printf("Warning: Failed to serialize packet %d, using original data: %v", i, err)
			
			// Если не удалось сериализовать, используем исходные данные
			packetData := packet.Data()
			if packetData == nil || len(packetData) == 0 {
				log.Printf("Error: Packet %d has no data (skipping)", i)
				dropped++
				continue
			}
			
			ci.Length = len(packetData)
			ci.CaptureLength = len(packetData)
			
			if err := writer.WritePacket(ci, packetData); err != nil {
				log.Printf("Error writing packet %d: %v", i, err)
				dropped++
			}
		} else {
			serializedData := buf.Bytes()
			ci.Length = len(serializedData)
			ci.CaptureLength = len(serializedData)
			
			if err := writer.WritePacket(ci, serializedData); err != nil {
				log.Printf("Error writing packet %d: %v", i, err)
				dropped++
			}
		}
	}
	
	log.Printf("Write summary: Total packets: %d, Dropped: %d", total, dropped)
	return nil
}

func getLinkType(packet gopacket.Packet) layers.LinkType {
	if linkLayer := packet.LinkLayer(); linkLayer != nil {
		layerType := linkLayer.LayerType()
		
		// Правильно маппим тип слоя на LinkType
		switch layerType {
		case layers.LayerTypeEthernet:
			return layers.LinkTypeEthernet
		case layers.LayerTypeDot1Q:
			return layers.LinkTypeEthernet
		case layers.LayerTypeLinuxSLL:
			return layers.LinkTypeLinuxSLL
		case layers.LayerTypeFDDI:
			return layers.LinkTypeFDDI
		case layers.LayerTypePPP:
			return layers.LinkTypePPP
		case layers.LayerTypePPPoE:
			return layers.LinkTypePPP
		default:
			// Для неизвестных типов используем Ethernet
			return layers.LinkTypeEthernet
		}
	}
	
	// По умолчанию используем Ethernet
	return layers.LinkTypeEthernet
}
