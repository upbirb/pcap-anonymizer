package anonymizer

import (
	"bytes"
	"fmt"
	"log"
	"net"
	"regexp"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// Глобальные переменные и счетчики
var (
	// Регулярные выражения для поиска
	sipPhoneRegex       = regexp.MustCompile(`(?i)(sip:)(\+?[0-9]{5,15})(@[^>\s;]+)`)
	sipDisplayNameRegex = regexp.MustCompile(`(?i)("?)(\+?[0-9]{5,15})("?\s*<sip:)(\+?[0-9]{5,15})(@)`)
	sipIPv4Regex        = regexp.MustCompile(`(?i)(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)`)
	sipIPv6Regex        = regexp.MustCompile(`(?i)\[?(?:(?:[0-9a-f]{1,4}:){7}[0-9a-f]{1,4}|(?:[0-9a-f]{1,4}:){1,7}:|(?:[0-9a-f]{1,4}:){1,6}:[0-9a-f]{1,4}|(?:[0-9a-f]{1,4}:){1,5}(?::[0-9a-f]{1,4}){1,2}|(?:[0-9a-f]{1,4}:){1,4}(?::[0-9a-f]{1,4}){1,3}|(?:[0-9a-f]{1,4}:){1,3}(?::[0-9a-f]{1,4}){1,4}|(?:[0-9a-f]{1,4}:){1,2}(?::[0-9a-f]{1,4}){1,5}|[0-9a-f]{1,4}:(?:(?::[0-9a-f]{1,4}){1,6})|:(?:(?::[0-9a-f]{1,4}){1,7}|:)|fe80:(?::[0-9a-f]{0,4}){0,4}%[0-9a-z]+|::(?:ffff(?::0{1,4})?:)?(?:(?:25[0-5]|(?:2[0-4]|1?[0-9])?[0-9])\.){3}(?:25[0-5]|(?:2[0-4]|1?[0-9])?[0-9])|(?:[0-9a-f]{1,4}:){1,4}:(?:(?:25[0-5]|(?:2[0-4]|1?[0-9])?[0-9])\.){3}(?:25[0-5]|(?:2[0-4]|1?[0-9])?[0-9]))\]?`)
	requestURIRegex     = regexp.MustCompile(`(?i)(sip:[^@]+@\[)([0-9a-f:]+)(\]:)`)
	// Определяем регулярное выражение для X-заголовков
	xHeaderRegex 		= regexp.MustCompile(`(?i)(X-[A-Za-z0-9_-]+:)\s*([^\r\n]+)`)

	// Маппинги
	sipPhoneMap        = make(map[string]string)
	modifiedPacketData = make(map[int][]byte) // Новая карта для хранения модифицированных данных

	// Счетчики
	nextPhoneID         = 1
	sipPacketsDetected  = 0
	sipPacketsModified  = 0
	phoneNumbersFound   = 0
	ipv4AddressesFound  = 0
	ipv6AddressesFound  = 0
	serializationErrors = 0

	// Карта для хранения анонимизированных идентификаторов пользователей
	userIDMap  = make(map[string]string)
	nextUserID = 1
)

// ProcessSIPPacket анонимизирует телефонные номера и IP-адреса в SIP-пакете
func ProcessSIPPacket(packet gopacket.Packet) bool {
	// Получаем уникальный идентификатор пакета
	packetID := int(packet.Metadata().CaptureInfo.Timestamp.UnixNano())

	log.Printf("[SIP] Processing packet ID: %d", packetID)

	// Проверяем наличие транспортного слоя
	transportLayer := packet.TransportLayer()
	if transportLayer == nil {
		log.Printf("[SIP] Packet %d has no transport layer", packetID)
		return false
	}

	var payload []byte
	var protocol string
	var transportLayerOffset int
	var isUDP bool

	// Определяем тип транспортного протокола
	switch transportLayer.LayerType() {
	case layers.LayerTypeTCP:
		tcp, _ := transportLayer.(*layers.TCP)
		payload = tcp.Payload
		protocol = "TCP"
		// Определяем смещение до payload
		transportLayerOffset = len(packet.Data()) - len(payload)
		log.Printf("[SIP] Packet %d is TCP with payload size: %d bytes, offset: %d",
			packetID, len(payload), transportLayerOffset)

	case layers.LayerTypeUDP:
		udp, _ := transportLayer.(*layers.UDP)
		payload = udp.Payload
		protocol = "UDP"
		isUDP = true
		// Определяем смещение до payload
		transportLayerOffset = len(packet.Data()) - len(payload)
		log.Printf("[SIP] Packet %d is UDP with payload size: %d bytes, offset: %d",
			packetID, len(payload), transportLayerOffset)

	default:
		log.Printf("[SIP] Packet %d has unsupported transport layer type: %s", packetID, transportLayer.LayerType())
		return false
	}

	// Проверяем, является ли это SIP-пакетом
	if len(payload) == 0 {
		log.Printf("[SIP] Packet %d has empty payload", packetID)
		return false
	}

	if !isSIPPacket(payload) {
		log.Printf("[SIP] Packet %d is not a SIP packet", packetID)
		return false
	}

	// Увеличиваем счетчик обнаруженных SIP-пакетов
	sipPacketsDetected++
	log.Printf("[SIP] Packet %d is a SIP packet over %s", packetID, protocol)

	// Выводим первые 100 байт SIP сообщения для отладки
	previewSize := 100
	if len(payload) < previewSize {
		previewSize = len(payload)
	}
	log.Printf("[SIP] Packet %d SIP preview: %s", packetID, string(payload[:previewSize]))

	// Анонимизируем SIP-содержимое
	newSipPayload, phoneCount, ipv4Count, ipv6Count := anonymizeSIPContent(payload)

	// Обновляем счетчики найденных элементов
	phoneNumbersFound += phoneCount
	ipv4AddressesFound += ipv4Count
	ipv6AddressesFound += ipv6Count

	// Если содержимое не изменилось, выходим
	if bytes.Equal(payload, newSipPayload) {
		log.Printf("[SIP] Packet %d content was not modified", packetID)
		return false
	}

	log.Printf("[SIP] Packet %d content was modified (found: %d phones, %d IPv4, %d IPv6)",
		packetID, phoneCount, ipv4Count, ipv6Count)

	// Увеличиваем счетчик модифицированных SIP-пакетов
	sipPacketsModified++

	// Создаем новые полные данные пакета
	originalData := packet.Data()
	newData := make([]byte, transportLayerOffset+len(newSipPayload))

	// Копируем заголовки из оригинального пакета
	copy(newData[:transportLayerOffset], originalData[:transportLayerOffset])

	// Копируем новый SIP payload
	copy(newData[transportLayerOffset:], newSipPayload)

	// Для UDP-пакетов, обновляем длину в заголовке UDP
	if isUDP {
		// UDP header: 8 байт, поле Length находится на смещении 4-6 байт
		udpHeaderOffset := transportLayerOffset - 8 // 8 байт - размер UDP заголовка
		if udpHeaderOffset >= 0 {
			// Длина UDP = длина заголовка (8 байт) + длина данных
			newLength := uint16(8 + len(newSipPayload))
			newData[udpHeaderOffset+4] = byte(newLength >> 8)   // Старший байт
			newData[udpHeaderOffset+5] = byte(newLength & 0xFF) // Младший байт
			log.Printf("[SIP] Packet %d updated UDP length field to %d", packetID, newLength)
		}
	}

	// Сохраняем модифицированные данные
	mapMutex.Lock()
	modifiedPacketData[packetID] = newData
	mapMutex.Unlock()

	log.Printf("[SIP] Packet %d stored modified data, size: %d bytes", packetID, len(newData))

	return true
}

// GetModifiedPacketData возвращает модифицированные данные пакета
func GetModifiedPacketData(packet gopacket.Packet) []byte {
	packetID := int(packet.Metadata().CaptureInfo.Timestamp.UnixNano())

	mapMutex.RLock()
	data := modifiedPacketData[packetID]
	mapMutex.RUnlock()

	if data != nil {
		log.Printf("[SIP] Found modified data for packet %d, size: %d bytes", packetID, len(data))
	}

	return data
}

// isSIPPacket определяет, является ли пакет SIP-пакетом
func isSIPPacket(payload []byte) bool {
	if len(payload) < 4 {
		return false
	}

	// Проверяем начало пакета на соответствие SIP-сообщению
	startsWith := func(prefix string) bool {
		return len(payload) >= len(prefix) &&
			bytes.Equal(bytes.ToUpper(payload[:len(prefix)]), bytes.ToUpper([]byte(prefix)))
	}

	// Проверяем на SIP-запросы и ответы
	if startsWith("SIP/2.0") ||
		startsWith("INVITE") ||
		startsWith("ACK") ||
		startsWith("BYE") ||
		startsWith("CANCEL") ||
		startsWith("OPTIONS") ||
		startsWith("REGISTER") ||
		startsWith("REFER") ||
		startsWith("NOTIFY") ||
		startsWith("SUBSCRIBE") ||
		startsWith("MESSAGE") ||
		startsWith("INFO") {
		return true
	}

	return false
}

// anonymizeSIPContent анонимизирует телефонные номера и IP-адреса в SIP-сообщении
// Возвращает модифицированный контент и счетчики найденных элементов
func anonymizeSIPContent(payload []byte) ([]byte, int, int, int) {
	content := string(payload)
	original := content

	// Счетчики для найденных элементов
	phoneCount := 0
	ipv4Count := 0
	ipv6Count := 0

	// Анонимизируем телефонные номера в SIP URI
	content = sipPhoneRegex.ReplaceAllStringFunc(content, func(match string) string {
		submatches := sipPhoneRegex.FindStringSubmatch(match)
		if len(submatches) >= 4 {
			prefix := submatches[1]
			phoneNumber := submatches[2]
			domain := submatches[3]

			// Анонимизируем телефонный номер
			anonPhone := getAnonymizedPhoneNumber(phoneNumber)

			log.Printf("[SIP] Anonymizing phone number in URI: %s -> %s", phoneNumber, anonPhone)
			phoneCount++

			return prefix + anonPhone + domain
		}
		return match
	})

	// Анонимизируем телефонные номера с отображаемым именем
	content = sipDisplayNameRegex.ReplaceAllStringFunc(content, func(match string) string {
		submatches := sipDisplayNameRegex.FindStringSubmatch(match)
		if len(submatches) >= 6 {
			quote1 := submatches[1]
			displayName := submatches[2]
			quote2AndBracket := submatches[3]
			phoneNumber := submatches[4]
			atSign := submatches[5]

			// Анонимизируем оба телефонных номера
			anonDisplayName := getAnonymizedPhoneNumber(displayName)
			anonPhone := getAnonymizedPhoneNumber(phoneNumber)

			log.Printf("[SIP] Anonymizing display name: %s -> %s", displayName, anonDisplayName)
			log.Printf("[SIP] Anonymizing phone in display name URI: %s -> %s", phoneNumber, anonPhone)
			phoneCount += 2

			return quote1 + anonDisplayName + quote2AndBracket + anonPhone + atSign
		}
		return match
	})

	// Анонимизируем IPv4 адреса в теле SIP сообщения
	content = sipIPv4Regex.ReplaceAllStringFunc(content, func(match string) string {
		ipStr := match

		// Парсим IP-адрес
		ip := net.ParseIP(ipStr)
		if ip == nil {
			return match
		}

		// Если IP-адрес уже является документационным, оставляем его как есть
		if IsDocumentationIPv4(ip) {
			log.Printf("[SIP] Skipping documentation IPv4: %s", ipStr)
			return ipStr
		}

		// Анонимизируем IPv4 адрес
		ipv4 := ip.To4()
		if ipv4 != nil {
			mapMutex.Lock()
			defer mapMutex.Unlock()

			// Проверяем, есть ли IP уже в кэше
			ipString := ipv4.String()

			var newIP net.IP
			var ok bool

			if IsPrivateIPv4(ipv4) {
				if newIP, ok = ipv4PrivateMap[ipString]; !ok {
					// Создаем новый анонимизированный IP
					if nextPrivateID >= 254 {
						nextPrivateID = 1 // Перезапускаем с начала
					}

					newIP = net.IPv4(192, 0, 2, nextPrivateID).To4()
					nextPrivateID++

					// Сохраняем анонимизированный IP
					ipv4PrivateMap[ipString] = newIP
				}
			} else {
				if newIP, ok = ipv4PublicMap[ipString]; !ok {
					// Создаем новый анонимизированный IP
					if nextPublicID >= 254 {
						nextPublicID = 1 // Перезапускаем с начала
					}

					newIP = net.IPv4(203, 0, 113, nextPublicID).To4()
					nextPublicID++

					// Сохраняем анонимизированный IP
					ipv4PublicMap[ipString] = newIP
				}
			}

			log.Printf("[SIP] Anonymizing IPv4 in SIP content: %s -> %s", ipString, newIP.String())
			ipv4Count++

			return newIP.String()
		}

		return match
	})

	// Анонимизируем IPv6 адреса в теле SIP сообщения
	content = sipIPv6Regex.ReplaceAllStringFunc(content, func(match string) string {
		// Убираем скобки, если они есть
		ipStr := match
		hasBrackets := false
		if len(ipStr) > 2 && ipStr[0] == '[' && ipStr[len(ipStr)-1] == ']' {
			hasBrackets = true
			ipStr = ipStr[1 : len(ipStr)-1]
		}

		// Парсим IPv6-адрес
		ip := net.ParseIP(ipStr)
		if ip == nil {
			return match
		}

		// Если IP-адрес уже является документационным, оставляем его как есть
		if IsDocumentationIPv6(ip) {
			log.Printf("[SIP] Skipping documentation IPv6: %s", ipStr)
			return match
		}

		// Анонимизируем IPv6 адрес
		ipv6 := ip.To16()
		if ipv6 != nil {
			mapMutex.Lock()
			defer mapMutex.Unlock()

			// Проверяем, есть ли IP уже в кэше
			ipString := ipv6.String()

			var newIP net.IP
			var ok bool

			if newIP, ok = ipv6Map[ipString]; !ok {
				// Создаем новый анонимизированный IP из диапазона 2001:db8::/32
				if nextIPv6Suffix >= 0xFFFFFFFFFFFFFFFF {
					nextIPv6Suffix = 1 // Перезапускаем с начала
				}

				newIP = make(net.IP, 16)
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
			}

			log.Printf("[SIP] Anonymizing IPv6 in SIP content: %s -> %s", ipString, newIP.String())
			ipv6Count++

			if hasBrackets {
				return "[" + newIP.String() + "]"
			}
			return newIP.String()
		}

		return match
	})

	// Дополнительный проход для IPv6 в Request-URI
	// Специально обрабатываем URI вида: sip:user@[IPv6]:port
	content = requestURIRegex.ReplaceAllStringFunc(content, func(match string) string {
		submatches := requestURIRegex.FindStringSubmatch(match)
		if len(submatches) >= 4 {
			prefix := submatches[1]
			ipv6Str := submatches[2]
			suffix := submatches[3]

			// Парсим IPv6-адрес
			ip := net.ParseIP(ipv6Str)
			if ip == nil {
				return match
			}

			// Если IP-адрес уже является документационным, оставляем его как есть
			if IsDocumentationIPv6(ip) {
				log.Printf("[SIP] Skipping documentation IPv6 in URI: %s", ipv6Str)
				return match
			}

			// Анонимизируем IPv6 адрес
			ipv6 := ip.To16()
			if ipv6 != nil {
				mapMutex.Lock()
				defer mapMutex.Unlock()

				// Проверяем, есть ли IP уже в кэше
				ipString := ipv6.String()

				var newIP net.IP
				var ok bool

				if newIP, ok = ipv6Map[ipString]; !ok {
					// Создаем новый анонимизированный IP из диапазона 2001:db8::/32
					if nextIPv6Suffix >= 0xFFFFFFFFFFFFFFFF {
						nextIPv6Suffix = 1 // Перезапускаем с начала
					}

					newIP = make(net.IP, 16)
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
				}

				log.Printf("[SIP] Anonymizing IPv6 in Request-URI: %s -> %s", ipString, newIP.String())
				ipv6Count++

				return prefix + newIP.String() + suffix
			}
		}

		return match
	})

	// Для X-заголовков и других нестандартных полей с чувствительными данными
	// Примеры:
	// X-Subscriber-ID: user1234
	// X-Account-Info: 1234567890
	// X-Forwarded-For: 192.168.1.1, 10.0.0.1
	content = xHeaderRegex.ReplaceAllStringFunc(content, func(match string) string {
		submatches := xHeaderRegex.FindStringSubmatch(match)
		if len(submatches) >= 3 {
			headerName := submatches[1]
			headerValue := submatches[2]

			log.Printf("[SIP] Processing X-header: %s %s", headerName, headerValue)

			// Анонимизируем телефонные номера в значении заголовка
			headerValue = anonymizePhoneNumbers(headerValue, &phoneCount)

			// Анонимизируем IPv4 адреса в значении заголовка
			headerValue = anonymizeIPv4InText(headerValue, &ipv4Count)

			// Анонимизируем IPv6 адреса в значении заголовка
			headerValue = anonymizeIPv6InText(headerValue, &ipv6Count)

			// Анонимизируем потенциальные идентификаторы пользователей и аккаунтов
			headerValue = anonymizeUserIDs(headerValue)

			return headerName + " " + headerValue
		}
		return match
	})

	// Проверяем, было ли изменено содержимое
	if content != original {
		log.Printf("[SIP] Content changed: %d bytes -> %d bytes", len(original), len(content))
	}

	return []byte(content), phoneCount, ipv4Count, ipv6Count
}

// getAnonymizedPhoneNumber возвращает анонимизированный телефонный номер
func getAnonymizedPhoneNumber(phoneNumber string) string {
	mapMutex.Lock()
	defer mapMutex.Unlock()

	if anonPhone, ok := sipPhoneMap[phoneNumber]; ok {
		return anonPhone
	}

	// Сохраняем "+", если он присутствует
	prefix := ""
	if len(phoneNumber) > 0 && phoneNumber[0] == '+' {
		prefix = "+"
		phoneNumber = phoneNumber[1:]
	}

	// Создаем анонимизированный номер, сохраняя длину оригинала
	anonPhone := fmt.Sprintf("%s%s%0*d", prefix, "555", len(phoneNumber)-3, nextPhoneID)
	nextPhoneID++

	sipPhoneMap[phoneNumber] = anonPhone
	return anonPhone
}

// GetSIPPhoneMappingStats возвращает статистику по анонимизации телефонных номеров
func GetSIPPhoneMappingStats() int {
	mapMutex.RLock()
	defer mapMutex.RUnlock()

	return len(sipPhoneMap)
}

// GetSIPStatsData возвращает общую статистику по обработке SIP-пакетов
func GetSIPStatsData() (detected, modified, phones, ipv4, ipv6, errors, userIDs int) {
    return sipPacketsDetected, sipPacketsModified, phoneNumbersFound, 
        ipv4AddressesFound, ipv6AddressesFound, serializationErrors, len(userIDMap)
}

// GetSampleUserIDMappings возвращает примеры анонимизированных идентификаторов пользователей
func GetSampleUserIDMappings(count int) map[string]string {
    mapMutex.RLock()
    defer mapMutex.RUnlock()
    
    idMap := make(map[string]string)
    
    // Получаем примеры идентификаторов
    i := 0
    for original, anonymized := range userIDMap {
        if i >= count {
            break
        }
        idMap[original] = anonymized
        i++
    }
    
    return idMap
}

// GetSampleSIPPhoneMappings возвращает примеры анонимизированных телефонных номеров
func GetSampleSIPPhoneMappings(count int) map[string]string {
	mapMutex.RLock()
	defer mapMutex.RUnlock()

	phoneMap := make(map[string]string)

	// Получаем примеры телефонных номеров
	i := 0
	for original, anonymized := range sipPhoneMap {
		if i >= count {
			break
		}
		phoneMap[original] = anonymized
		i++
	}

	return phoneMap
}

// anonymizePhoneNumbers анонимизирует все телефонные номера в тексте
func anonymizePhoneNumbers(text string, count *int) string {
    // Для телефонных номеров без контекста (просто числа длиной 7-15 цифр)
    // Используем простое регулярное выражение, совместимое с Go
    phonePattern := regexp.MustCompile(`(\+?[0-9]{7,15})`)
    
    return phonePattern.ReplaceAllStringFunc(text, func(match string) string {
        // Проверяем, что это телефонный номер, а не часть другого текста
        // Проверяем символы до и после телефонного номера
        index := strings.Index(text, match)
        if index > 0 {
            prevChar := text[index-1]
            // Если предыдущий символ - буква или цифра, считаем это частью другого слова
            if (prevChar >= 'a' && prevChar <= 'z') || 
               (prevChar >= 'A' && prevChar <= 'Z') || 
               (prevChar >= '0' && prevChar <= '9') {
                return match
            }
        }
        
        // Проверяем символ после телефонного номера
        afterIndex := index + len(match)
        if afterIndex < len(text) {
            nextChar := text[afterIndex]
            // Если следующий символ - буква или цифра, считаем это частью другого слова
            if (nextChar >= 'a' && nextChar <= 'z') || 
               (nextChar >= 'A' && nextChar <= 'Z') || 
               (nextChar >= '0' && nextChar <= '9') {
                return match
            }
        }
        
        // Игнорируем очевидно не телефонные числа (например, порты, timestamp и т.д.)
        if len(match) < 7 || strings.Contains(match, ".") {
            return match
        }
        
        // Анонимизируем телефонный номер
        anonPhone := getAnonymizedPhoneNumber(match)
        log.Printf("[SIP] Anonymizing phone number in X-header: %s -> %s", match, anonPhone)
        *count++
        
        return anonPhone
    })
}

// anonymizeIPv4InText анонимизирует все IPv4 адреса в тексте
func anonymizeIPv4InText(text string, count *int) string {
    return sipIPv4Regex.ReplaceAllStringFunc(text, func(match string) string {
        // Повторяем логику анонимизации IPv4, как в основной функции
        ip := net.ParseIP(match)
        if ip == nil {
            return match
        }
        
        if IsDocumentationIPv4(ip) {
            return match
        }
        
        ipv4 := ip.To4()
        if ipv4 != nil {
            mapMutex.Lock()
            defer mapMutex.Unlock()
            
            ipString := ipv4.String()
            
            var newIP net.IP
            var ok bool
            
            if IsPrivateIPv4(ipv4) {
                if newIP, ok = ipv4PrivateMap[ipString]; !ok {
                    if nextPrivateID >= 254 {
                        nextPrivateID = 1
                    }
                    
                    newIP = net.IPv4(192, 0, 2, nextPrivateID).To4()
                    nextPrivateID++
                    
                    ipv4PrivateMap[ipString] = newIP
                }
            } else {
                if newIP, ok = ipv4PublicMap[ipString]; !ok {
                    if nextPublicID >= 254 {
                        nextPublicID = 1
                    }
                    
                    newIP = net.IPv4(203, 0, 113, nextPublicID).To4()
                    nextPublicID++
                    
                    ipv4PublicMap[ipString] = newIP
                }
            }
            
            log.Printf("[SIP] Anonymizing IPv4 in X-header: %s -> %s", ipString, newIP.String())
            *count++
            
            return newIP.String()
        }
        
        return match
    })
}

// anonymizeIPv6InText анонимизирует все IPv6 адреса в тексте
func anonymizeIPv6InText(text string, count *int) string {
    return sipIPv6Regex.ReplaceAllStringFunc(text, func(match string) string {
        // Повторяем логику анонимизации IPv6, как в основной функции
        // Убираем скобки, если они есть
        ipStr := match
        hasBrackets := false
        if len(ipStr) > 2 && ipStr[0] == '[' && ipStr[len(ipStr)-1] == ']' {
            hasBrackets = true
            ipStr = ipStr[1 : len(ipStr)-1]
        }
        
        ip := net.ParseIP(ipStr)
        if ip == nil {
            return match
        }
        
        if IsDocumentationIPv6(ip) {
            return match
        }
        
        ipv6 := ip.To16()
        if ipv6 != nil {
            mapMutex.Lock()
            defer mapMutex.Unlock()
            
            ipString := ipv6.String()
            
            var newIP net.IP
            var ok bool
            
            if newIP, ok = ipv6Map[ipString]; !ok {
                if nextIPv6Suffix >= 0xFFFFFFFFFFFFFFFF {
                    nextIPv6Suffix = 1
                }
                
                newIP = make(net.IP, 16)
                copy(newIP, net.ParseIP("2001:db8::"))
                
                suffix := nextIPv6Suffix
                for i := 15; i >= 8; i-- {
                    newIP[i] = byte(suffix & 0xFF)
                    suffix >>= 8
                }
                
                nextIPv6Suffix++
                
                ipv6Map[ipString] = newIP
            }
            
            log.Printf("[SIP] Anonymizing IPv6 in X-header: %s -> %s", ipString, newIP.String())
            *count++
            
            if hasBrackets {
                return "[" + newIP.String() + "]"
            }
            return newIP.String()
        }
        
        return match
    })
}

// anonymizeUserIDs анонимизирует идентификаторы пользователей и другие чувствительные данные
func anonymizeUserIDs(text string) string {
    // Шаблоны для идентификаторов пользователей и аккаунтов
    // Примеры: user1234, account_567, subscriber-890, etc.
    userIDPatterns := []*regexp.Regexp{
        regexp.MustCompile(`(?i)user[_-]?([0-9a-f]{4,})`),               // user1234, user_1234, etc.
        regexp.MustCompile(`(?i)acc(oun)?t[_-]?([0-9a-f]{4,})`),         // account1234, acct_1234, etc.
        regexp.MustCompile(`(?i)subscr(iber)?[_-]?([0-9a-f]{4,})`),      // subscriber1234, subscr_1234, etc.
        regexp.MustCompile(`(?i)cust(omer)?[_-]?([0-9a-f]{4,})`),        // customer1234, cust_1234, etc.
        regexp.MustCompile(`(?i)id[_-]?([0-9a-f]{6,})`),                 // id123456, id_123456, etc.
    }
    
    result := text
    
    // Применяем все шаблоны
    for _, pattern := range userIDPatterns {
        result = pattern.ReplaceAllStringFunc(result, func(match string) string {
            mapMutex.Lock()
            defer mapMutex.Unlock()
            
            if anonID, ok := userIDMap[match]; ok {
                return anonID
            }
            
            // Создаем новый анонимизированный ID
            prefix := "anonymous"
            if strings.HasPrefix(strings.ToLower(match), "user") {
                prefix = "user"
            } else if strings.Contains(strings.ToLower(match), "acc") {
                prefix = "account"
            } else if strings.Contains(strings.ToLower(match), "subscr") {
                prefix = "subscriber"
            } else if strings.Contains(strings.ToLower(match), "cust") {
                prefix = "customer"
            } else if strings.Contains(strings.ToLower(match), "id") {
                prefix = "id"
            }
            
            anonID := fmt.Sprintf("%s%d", prefix, nextUserID)
            nextUserID++
            
            userIDMap[match] = anonID
            log.Printf("[SIP] Anonymizing user ID in X-header: %s -> %s", match, anonID)
            
            return anonID
        })
    }
    
    return result
}