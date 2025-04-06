package anonymizer

import (
	"net"
	"sync"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// Глобальные карты и счетчики для согласованной анонимизации
var (
	ipv4PrivateMap = make(map[string]net.IP)
	ipv4PublicMap  = make(map[string]net.IP)
	ipv6Map        = make(map[string]net.IP)
	mapMutex       sync.RWMutex
	nextPrivateID  = byte(1)
	nextPublicID   = byte(1)
	nextIPv6Suffix = uint64(1)
)

// Config содержит настройки для анонимизации
type Config struct {
	VerboseLogging bool
	ProcessIP      bool
	ProcessSIP     bool
}

// NewConfig создает новую конфигурацию с значениями по умолчанию
func NewConfig() *Config {
	return &Config{
		VerboseLogging: false,
		ProcessIP:      true,
		ProcessSIP:     true,
	}
}

// Process обрабатывает пакет и анонимизирует IP-адреса и SIP-данные
func Process(packet gopacket.Packet, cfg *Config) bool {
	modified := false
	
	// Анонимизируем IP-адреса на сетевом уровне
	if cfg.ProcessIP {
		if ProcessNetworkLayer(packet) {
			modified = true
		}
	}
	
	// Анонимизируем SIP-данные
	if cfg.ProcessSIP {
		if ProcessSIPPacket(packet) {
			modified = true
		}
	}
	
	return modified
}

// ProcessNetworkLayer анонимизирует IP-адреса на сетевом уровне
func ProcessNetworkLayer(packet gopacket.Packet) bool {
	modified := false
	
	// Обработка IPv4
	if ipv4Layer := packet.Layer(layers.LayerTypeIPv4); ipv4Layer != nil {
		ipv4, _ := ipv4Layer.(*layers.IPv4)
		
		// Анонимизируем исходный IP-адрес
		srcModified := anonymizeIPv4(ipv4.SrcIP)
		
		// Анонимизируем IP-адрес назначения
		dstModified := anonymizeIPv4(ipv4.DstIP)
		
		if srcModified || dstModified {
			modified = true
			
			// Обновляем контрольную сумму
			ipv4.Checksum = 0 // Сбрасываем, чтобы пересчитать
		}
	}
	
	// Обработка IPv6
	if ipv6Layer := packet.Layer(layers.LayerTypeIPv6); ipv6Layer != nil {
		ipv6, _ := ipv6Layer.(*layers.IPv6)
		
		// Анонимизируем исходный IP-адрес
		srcModified := anonymizeIPv6(ipv6.SrcIP)
		
		// Анонимизируем IP-адрес назначения
		dstModified := anonymizeIPv6(ipv6.DstIP)
		
		if srcModified || dstModified {
			modified = true
		}
	}
	
	return modified
}

// IsPrivateIPv4 проверяет, является ли IPv4-адрес приватным
func IsPrivateIPv4(ip net.IP) bool {
	privateBlocks := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"127.0.0.0/8",    // Локальный адрес
		"169.254.0.0/16", // Link-local
		"0.0.0.0/8",      // Текущая сеть
	}
	
	for _, block := range privateBlocks {
		_, ipnet, _ := net.ParseCIDR(block)
		if ipnet.Contains(ip) {
			return true
		}
	}
	return false
}

// IsDocumentationIPv4 проверяет, является ли IPv4-адрес документационным
func IsDocumentationIPv4(ip net.IP) bool {
	_, docNet1, _ := net.ParseCIDR("192.0.2.0/24")
	_, docNet2, _ := net.ParseCIDR("203.0.113.0/24")
	_, testNet, _ := net.ParseCIDR("198.51.100.0/24") // Тоже документационная сеть
	return docNet1.Contains(ip) || docNet2.Contains(ip) || testNet.Contains(ip)
}

// IsDocumentationIPv6 проверяет, является ли IPv6-адрес документационным
func IsDocumentationIPv6(ip net.IP) bool {
	_, docNet, _ := net.ParseCIDR("2001:db8::/32")
	return docNet.Contains(ip)
}

// AnonymizeIPv4 анонимизирует IPv4-адрес (публичный API)
func AnonymizeIPv4(ip net.IP) bool {
	return anonymizeIPv4(ip)
}

// anonymizeIPv4 анонимизирует IPv4-адрес (внутренняя реализация)
func anonymizeIPv4(ip net.IP) bool {
	// Если адрес уже является документационным, оставляем его как есть
	if IsDocumentationIPv4(ip) {
		return false
	}
	
	ipString := ip.String()
	
	// Проверяем, был ли IP уже анонимизирован
	mapMutex.RLock()
	if IsPrivateIPv4(ip) {
		if anonIP, ok := ipv4PrivateMap[ipString]; ok {
			mapMutex.RUnlock()
			// Копируем анонимизированный IP в оригинальный
			copy(ip, anonIP.To4())
			return true
		}
	} else {
		if anonIP, ok := ipv4PublicMap[ipString]; ok {
			mapMutex.RUnlock()
			// Копируем анонимизированный IP в оригинальный
			copy(ip, anonIP.To4())
			return true
		}
	}
	mapMutex.RUnlock()
	
	// Создаем новый анонимизированный IP
	mapMutex.Lock()
	defer mapMutex.Unlock()
	
	// Повторная проверка после блокировки
	if IsPrivateIPv4(ip) {
		if anonIP, ok := ipv4PrivateMap[ipString]; ok {
			// Копируем анонимизированный IP в оригинальный
			copy(ip, anonIP.To4())
			return true
		}
		
		// Создаем новый анонимизированный IP
		if nextPrivateID >= 254 {
			nextPrivateID = 1 // Перезапускаем с начала
		}
		
		newIP := net.IPv4(192, 0, 2, nextPrivateID).To4()
		nextPrivateID++
		
		// Сохраняем анонимизированный IP
		ipv4PrivateMap[ipString] = newIP
		
		// Копируем анонимизированный IP в оригинальный
		copy(ip, newIP)
		return true
	} else {
		if anonIP, ok := ipv4PublicMap[ipString]; ok {
			// Копируем анонимизированный IP в оригинальный
			copy(ip, anonIP.To4())
			return true
		}
		
		// Создаем новый анонимизированный IP
		if nextPublicID >= 254 {
			nextPublicID = 1 // Перезапускаем с начала
		}
		
		newIP := net.IPv4(203, 0, 113, nextPublicID).To4()
		nextPublicID++
		
		// Сохраняем анонимизированный IP
		ipv4PublicMap[ipString] = newIP
		
		// Копируем анонимизированный IP в оригинальный
		copy(ip, newIP)
		return true
	}
}

// AnonymizeIPv6 анонимизирует IPv6-адрес (публичный API)
func AnonymizeIPv6(ip net.IP) bool {
	return anonymizeIPv6(ip)
}

// anonymizeIPv6 анонимизирует IPv6-адрес (внутренняя реализация)
func anonymizeIPv6(ip net.IP) bool {
	// Если адрес уже является документационным, оставляем его как есть
	if IsDocumentationIPv6(ip) {
		return false
	}
	
	ipString := ip.String()
	
	// Проверяем, был ли IP уже анонимизирован
	mapMutex.RLock()
	if anonIP, ok := ipv6Map[ipString]; ok {
		mapMutex.RUnlock()
		// Копируем анонимизированный IP в оригинальный
		copy(ip, anonIP)
		return true
	}
	mapMutex.RUnlock()
	
	// Создаем новый анонимизированный IP
	mapMutex.Lock()
	defer mapMutex.Unlock()
	
	// Повторная проверка после блокировки
	if anonIP, ok := ipv6Map[ipString]; ok {
		// Копируем анонимизированный IP в оригинальный
		copy(ip, anonIP)
		return true
	}
	
	// Создаем новый анонимизированный IP из диапазона 2001:db8::/32
	if nextIPv6Suffix >= 0xFFFFFFFFFFFFFFFF {
		nextIPv6Suffix = 1 // Перезапускаем с начала
	}
	
	newIP := make(net.IP, 16)
	copy(newIP, net.ParseIP("2001:db8::"))
	
	// Заполняем последние 8 байт суффиксом
	suffix := nextIPv6Suffix
	for i := 15; i >= 8; i-- {
		newIP[i] = byte(suffix & 0xFF)
		suffix >>= 8
	}
	
	nextIPv6Suffix++
	
	// Сохраняем анонимизированный IP
	ipv6Map[ipString] = newIP
	
	// Копируем анонимизированный IP в оригинальный
	copy(ip, newIP)
	
	return true
}

// GetIPMappingStats возвращает статистику по анонимизированным IP-адресам
func GetIPMappingStats() (privateIPv4, publicIPv4, ipv6 int) {
	mapMutex.RLock()
	defer mapMutex.RUnlock()
	
	return len(ipv4PrivateMap), len(ipv4PublicMap), len(ipv6Map)
}

// GetSampleIPMappings возвращает примеры анонимизированных IP-адресов
func GetSampleIPMappings(count int) (privateMap, publicMap, ipv6Maps map[string]string) {
	mapMutex.RLock()
	defer mapMutex.RUnlock()
	
	privateMap = make(map[string]string)
	publicMap = make(map[string]string)
	ipv6Maps = make(map[string]string)
	
	// Получаем примеры приватных IPv4
	i := 0
	for original, anonymized := range ipv4PrivateMap {
		if i >= count {
			break
		}
		privateMap[original] = anonymized.String()
		i++
	}
	
	// Получаем примеры публичных IPv4
	i = 0
	for original, anonymized := range ipv4PublicMap {
		if i >= count {
			break
		}
		publicMap[original] = anonymized.String()
		i++
	}
	
	// Получаем примеры IPv6
	i = 0
	for original, anonymized := range ipv6Map {
		if i >= count {
			break
		}
		ipv6Maps[original] = anonymized.String()
		i++
	}
	
	return privateMap, publicMap, ipv6Maps
}
