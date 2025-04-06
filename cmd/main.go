package main

import (
	"fmt"
	"log"
	"os"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	"github.com/upbirb/pcap-anonymizer/internal/anonymizer"
	"github.com/upbirb/pcap-anonymizer/internal/pcap"
)

func main() {
	verbose := false
	
	if len(os.Args) < 3 {
		fmt.Println("Usage: pcap-anon <input.pcap> <output.pcap> [-v]")
		os.Exit(1)
	}

	// Получаем имена файлов из аргументов командной строки
	inputFile := os.Args[1]
	outputFile := os.Args[2]
	
	// Проверяем, существует ли входной файл
	if _, err := os.Stat(inputFile); os.IsNotExist(err) {
		fmt.Fprintf(os.Stderr, "Error: input file %s does not exist\n", inputFile)
		os.Exit(1)
	}

	// Создаем конфигурацию
	cfg := anonymizer.NewConfig()
	
	// Обрабатываем флаги
	for i := 3; i < len(os.Args); i++ {
		if os.Args[i] == "-v" {
			verbose = true
			cfg.VerboseLogging = true
			log.Println("Verbose logging enabled")
		}
	}

	// Замеряем время выполнения
	startTime := time.Now()
	
	// Читаем пакеты из входного файла
	log.Printf("Reading packets from %s...", inputFile)
	packets, err := pcap.ReadPackets(inputFile)
	if err != nil {
		log.Fatalf("Error reading packets: %v", err)
	}
	log.Printf("Successfully read %d packets", len(packets))

	// Статистика
	stats := struct {
		total, modified, ipv4Modified, ipv6Modified int
	}{}

	// Обрабатываем пакеты
	log.Println("Processing packets...")
	for i, packet := range packets {
		stats.total++

		// Показываем прогресс каждые 1000 пакетов
		if i%1000 == 0 && i > 0 {
			fmt.Printf("\rProcessed %d/%d packets...", i, len(packets))
		}

		// Получаем IP-адреса до анонимизации
		beforeSrc, beforeDst := getPacketIPs(packet)
		
		// Анонимизируем IP-адреса на сетевом уровне
		if anonymizer.Process(packet, cfg) {
			stats.modified++
			
			// Определяем тип модифицированного пакета
			if packet.Layer(layers.LayerTypeIPv4) != nil {
				stats.ipv4Modified++
			} else if packet.Layer(layers.LayerTypeIPv6) != nil {
				stats.ipv6Modified++
			}
			
			// Обновляем контрольные суммы
			anonymizer.UpdateChecksums(packet)
		}
		
		// Получаем IP-адреса после анонимизации
		afterSrc, afterDst := getPacketIPs(packet)
		
		// Если включено подробное логирование или адреса изменились, выводим информацию
		if verbose || (beforeSrc != afterSrc || beforeDst != afterDst) {
			log.Printf("Packet %d: %s → %s => %s → %s", 
				i, beforeSrc, beforeDst, afterSrc, afterDst)
		}
	}
	fmt.Println() // Перевод строки после индикатора прогресса

	// Записываем модифицированные пакеты в выходной файл
	log.Printf("Writing anonymized packets to %s...", outputFile)
	if err := pcap.WritePackets(outputFile, packets); err != nil {
		log.Fatalf("Error writing output: %v", err)
	}

	// Получаем статистику
	privateCount, publicCount, ipv6Count := anonymizer.GetIPMappingStats()
	
	// Получаем примеры анонимизированных IP-адресов
	privateMap, publicMap, ipv6Map := anonymizer.GetSampleIPMappings(5)

	// Выводим общую статистику
	duration := time.Since(startTime)
	fmt.Printf(`
Processing results:
- Total packets:      %d
- Modified packets:   %d
- IPv4 modified:      %d
- IPv6 modified:      %d
- Processing time:    %s

IP Anonymization:
- Private IPv4:       %d unique addresses
- Public IPv4:        %d unique addresses
- IPv6:               %d unique addresses
`, stats.total, stats.modified, stats.ipv4Modified, stats.ipv6Modified, 
   duration, privateCount, publicCount, ipv6Count)

	// Выводим примеры анонимизированных IP-адресов
	fmt.Println("\nExample IPv4 Private mappings:")
	for original, anonymized := range privateMap {
		fmt.Printf("  %s -> %s\n", original, anonymized)
	}
	
	fmt.Println("\nExample IPv4 Public mappings:")
	for original, anonymized := range publicMap {
		fmt.Printf("  %s -> %s\n", original, anonymized)
	}
	
	fmt.Println("\nExample IPv6 mappings:")
	for original, anonymized := range ipv6Map {
		fmt.Printf("  %s -> %s\n", original, anonymized)
	}
}

// getPacketIPs возвращает исходный и целевой IP-адреса пакета
func getPacketIPs(packet gopacket.Packet) (string, string) {
	if net := packet.NetworkLayer(); net != nil {
		switch v := net.(type) {
		case *layers.IPv4:
			return v.SrcIP.String(), v.DstIP.String()
		case *layers.IPv6:
			return v.SrcIP.String(), v.DstIP.String()
		}
	}
	return "", ""
}
