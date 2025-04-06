package pcap

import (
	"log"
	"os"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	
	"github.com/upbirb/pcap-anonymizer/internal/anonymizer"
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
	modified := 0
	originalData := 0
	serialized := 0

	for i, packet := range packets {
		total++
		packetID := int(packet.Metadata().CaptureInfo.Timestamp.UnixNano())
		
		log.Printf("[WRITER] Processing packet %d (ID: %d)", i, packetID)
		
		// Сохраняем информацию о времени захвата
		ci := packet.Metadata().CaptureInfo
		
		// Выбираем данные для записи
		var packetData []byte
		var dataSource string
		
		// Проверяем наличие модифицированных данных
		modData := anonymizer.GetModifiedPacketData(packet)
		
		if modData != nil {
			// Используем модифицированные данные
			packetData = modData
			dataSource = "modified cache"
			modified++
			log.Printf("[WRITER] Packet %d using modified data from cache, size: %d bytes", i, len(packetData))
		} else {
			// Используем оригинальные данные
			packetData = packet.Data()
			dataSource = "original"
			originalData++
			
			if packetData != nil {
				log.Printf("[WRITER] Packet %d using original data, size: %d bytes", i, len(packetData))
			}
		}
		
		if packetData == nil || len(packetData) == 0 {
			log.Printf("[WRITER] Packet %d has no data, trying to serialize", i)
			
			// Попробуем получить данные через сериализацию
			buf := gopacket.NewSerializeBuffer()
			opts := gopacket.SerializeOptions{
				FixLengths:       true,
				ComputeChecksums: true,
			}
			
			err := gopacket.SerializePacket(buf, opts, packet)
			if err != nil {
				log.Printf("[WRITER] ERROR: Failed to serialize packet %d: %v", i, err)
			} else {
				packetData = buf.Bytes()
				dataSource = "serialized"
				serialized++
				log.Printf("[WRITER] Packet %d successfully serialized, size: %d bytes", i, len(packetData))
			}
		}
		
		if packetData == nil || len(packetData) == 0 {
			log.Printf("[WRITER] ERROR: Packet %d has no data, skipping", i)
			dropped++
			continue
		}
		
		// Обновляем длину на всякий случай, если пакет был модифицирован
		ci.Length = len(packetData)
		ci.CaptureLength = len(packetData)
		
		log.Printf("[WRITER] Writing packet %d (%s data), CaptureLength: %d, Length: %d", 
			i, dataSource, ci.CaptureLength, ci.Length)
		
		if err := writer.WritePacket(ci, packetData); err != nil {
			log.Printf("[WRITER] ERROR: Failed to write packet %d: %v", i, err)
			dropped++
		} else {
			log.Printf("[WRITER] Successfully wrote packet %d", i)
		}
	}
	
	log.Printf("[WRITER] Summary: Total: %d, Modified: %d, Original: %d, Serialized: %d, Dropped: %d", 
		total, modified, originalData, serialized, dropped)
	
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
