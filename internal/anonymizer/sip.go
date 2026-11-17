package anonymizer

import (
	"bytes"
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// Глобальные переменные и счетчики
var (
	// Регулярные выражения для поиска
	sipPlainPhoneRegex  = regexp.MustCompile(`\+?[0-9]{7,15}`)
	sipPhoneRegex       = regexp.MustCompile(`(?i)(sip:)(\+?[0-9]{5,15})(@[^>\s;]+)`)
	sipDisplayNameRegex = regexp.MustCompile(`(?i)("?)(\+?[0-9]{5,15})("?\s*<sip:)(\+?[0-9]{5,15})(@)`)
	// Определяем регулярное выражение для X-заголовков
	xHeaderRegex = regexp.MustCompile(`(?i)(X-[A-Za-z0-9_-]+:)\s*([^\r\n]+)`)

	// Маппинги
	sipPhoneMap        = make(map[string]string)
	modifiedPacketData = make(map[gopacket.Packet][]byte) // Новая карта для хранения модифицированных данных

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
	return processSIPPacket(packet, nil)
}

func processSIPPacket(packet gopacket.Packet, cfg *Config) bool {
	// Проверяем наличие транспортного слоя
	transportLayer := packet.TransportLayer()
	if transportLayer == nil {
		cfg.debugf("SIP: skipped (no transport layer)")
		return false
	}

	var payload []byte
	var transportLayerOffset int
	var isUDP bool

	// Определяем тип транспортного протокола
	switch transportLayer.LayerType() {
	case layers.LayerTypeTCP:
		tcp, _ := transportLayer.(*layers.TCP)
		payload = tcp.Payload
		// Определяем смещение до payload
		transportLayerOffset = len(packet.Data()) - len(payload)

	case layers.LayerTypeUDP:
		udp, _ := transportLayer.(*layers.UDP)
		payload = udp.Payload
		isUDP = true
		// Определяем смещение до payload
		transportLayerOffset = len(packet.Data()) - len(payload)

	default:
		cfg.debugf("SIP: skipped (unsupported transport)")
		return false
	}

	// Проверяем, является ли это SIP-пакетом
	if len(payload) == 0 {
		cfg.debugf("SIP: skipped (empty payload)")
		return false
	}

	if !isSIPPacket(payload) {
		cfg.debugf("SIP: skipped (payload not recognized as SIP)")
		return false
	}

	// Увеличиваем счетчик обнаруженных SIP-пакетов
	sipPacketsDetected++
	cfg.debugf("SIP: detected protocol=%s payload_bytes=%d", transportLayer.LayerType(), len(payload))

	// Анонимизируем SIP-содержимое
	newSipPayload, phoneCount, ipv4Count, ipv6Count := anonymizeSIPContent(payload)
	cfg.debugf("SIP: replacements phones=%d ipv4=%d ipv6=%d; payload_bytes=%d -> %d",
		phoneCount, ipv4Count, ipv6Count, len(payload), len(newSipPayload))

	// Обновляем счетчики найденных элементов
	phoneNumbersFound += phoneCount
	ipv4AddressesFound += ipv4Count
	ipv6AddressesFound += ipv6Count

	// Если содержимое не изменилось, выходим
	if bytes.Equal(payload, newSipPayload) {
		cfg.debugf("SIP: content unchanged")
		return false
	}

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
		}
	}

	// Сохраняем модифицированные данные
	mapMutex.Lock()
	modifiedPacketData[packet] = newData
	mapMutex.Unlock()
	cfg.debugf("SIP: replacement stored packet_bytes=%d", len(newData))

	return true
}

// GetModifiedPacketData возвращает модифицированные данные пакета
func GetModifiedPacketData(packet gopacket.Packet) []byte {
	mapMutex.RLock()
	data := modifiedPacketData[packet]
	mapMutex.RUnlock()

	return data
}

// isSIPPacket recognizes a complete SIP/2.0 request/status line (RFC 3261,
// sections 7 and 25.1). Extension methods use the same token syntax as standard
// methods, so recognition must not depend on an enumerated method list.
// This identifies messages; it does not validate all headers or assemble TCP.
func isSIPPacket(payload []byte) bool {
	end := bytes.Index(payload, []byte("\r\n"))
	if end < 0 {
		return false
	}
	line := string(payload[:end])
	if strings.ContainsAny(line, "\r\n") {
		return false
	}
	first, rest, ok := strings.Cut(line, " ")
	if !ok {
		return false
	}
	second, third, ok := strings.Cut(rest, " ")
	if !ok {
		return false
	}
	if strings.EqualFold(first, "SIP/2.0") {
		// Reason-Phrase may contain spaces or be empty. The status is exactly
		// three digits, including extension codes described by the SIP grammar.
		return len(second) == 3 && second[0] >= '0' && second[0] <= '9' &&
			second[1] >= '0' && second[1] <= '9' && second[2] >= '0' && second[2] <= '9'
	}
	if !isSIPMethodToken(first) || !strings.EqualFold(third, "SIP/2.0") {
		return false
	}
	// Request-URI is absolute: SIP/SIPS and other schemes such as tel are valid.
	target, err := url.ParseRequestURI(second)
	return err == nil && target.IsAbs() && (target.Opaque != "" || target.Host != "" || target.Path != "")
}

func isSIPMethodToken(method string) bool {
	if method == "" {
		return false
	}
	for i := 0; i < len(method); i++ {
		c := method[i]
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' {
			continue
		}
		if !strings.ContainsRune("-.!%*_+`'~", rune(c)) {
			return false
		}
	}
	return true
}

// anonymizeSIPContent анонимизирует телефонные номера и IP-адреса в SIP-сообщении
// Возвращает модифицированный контент и счетчики найденных элементов
func anonymizeSIPContent(payload []byte) ([]byte, int, int, int) {
	content := string(payload)

	// Счетчики для найденных элементов
	phoneCount := 0
	ipv4Count := 0
	ipv6Count := 0

	// Анонимизируем телефонные номера с отображаемым именем
	content = sipDisplayNameRegex.ReplaceAllStringFunc(content, func(match string) string {
		submatches := sipDisplayNameRegex.FindStringSubmatch(match)
		if len(submatches) >= 6 {
			quote1 := submatches[1]
			displayName := submatches[2]
			quote2AndBracket := submatches[3]
			phoneNumber := submatches[4]
			atSign := submatches[5]

			// URI обрабатывается следующим проходом; здесь меняем только имя.
			anonDisplayName := getAnonymizedPhoneNumber(displayName)

			phoneCount++

			return quote1 + anonDisplayName + quote2AndBracket + phoneNumber + atSign
		}
		return match
	})

	// Анонимизируем телефонные номера в SIP URI
	content = sipPhoneRegex.ReplaceAllStringFunc(content, func(match string) string {
		submatches := sipPhoneRegex.FindStringSubmatch(match)
		if len(submatches) >= 4 {
			prefix := submatches[1]
			phoneNumber := submatches[2]
			domain := submatches[3]

			// Анонимизируем телефонный номер
			anonPhone := getAnonymizedPhoneNumber(phoneNumber)

			phoneCount++

			return prefix + anonPhone + domain
		}
		return match
	})

	content, ipv4Count, ipv6Count = anonymizeSIPAddresses(content)

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

			// Анонимизируем телефонные номера в значении заголовка
			headerValue = anonymizePhoneNumbers(headerValue, &phoneCount)

			// Анонимизируем потенциальные идентификаторы пользователей и аккаунтов
			headerValue = anonymizeUserIDs(headerValue)

			return headerName + " " + headerValue
		}
		return match
	})

	if head, body, ok := strings.Cut(content, "\r\n\r\n"); ok {
		lines := strings.Split(head, "\r\n")
		for i, line := range lines {
			name, _, found := strings.Cut(line, ":")
			if found && (strings.EqualFold(name, "Content-Length") || strings.EqualFold(name, "l")) {
				lines[i] = name + fmt.Sprintf(": %d", len(body))
			}
		}
		content = strings.Join(lines, "\r\n") + "\r\n\r\n" + body
	}

	return []byte(content), phoneCount, ipv4Count, ipv6Count
}

// getAnonymizedPhoneNumber возвращает анонимизированный телефонный номер
func getAnonymizedPhoneNumber(phoneNumber string) string {
	mapMutex.Lock()
	defer mapMutex.Unlock()

	originalNumber := phoneNumber

	if anonPhone, ok := sipPhoneMap[originalNumber]; ok {
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

	sipPhoneMap[originalNumber] = anonPhone
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

// anonymizePhoneNumbers replaces standalone phone numbers in extension headers.
// Boundaries are checked at each match's original byte offsets: an identical
// number may be part of an identifier at one position and standalone elsewhere.
func anonymizePhoneNumbers(text string, count *int) string {
	isAlphanumeric := func(c byte) bool {
		return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
	}
	var result strings.Builder
	last := 0
	for _, span := range sipPlainPhoneRegex.FindAllStringIndex(text, -1) {
		start, end := span[0], span[1]
		if start > 0 && isAlphanumeric(text[start-1]) || end < len(text) && isAlphanumeric(text[end]) {
			continue
		}
		result.WriteString(text[last:start])
		result.WriteString(getAnonymizedPhoneNumber(text[start:end]))
		last = end
		(*count)++
	}
	if last == 0 {
		return text
	}
	result.WriteString(text[last:])
	return result.String()
}

// anonymizeUserIDs анонимизирует идентификаторы пользователей и другие чувствительные данные
func anonymizeUserIDs(text string) string {
	// Шаблоны для идентификаторов пользователей и аккаунтов
	// Примеры: user1234, account_567, subscriber-890, etc.
	userIDPatterns := []*regexp.Regexp{
		regexp.MustCompile(`(?i)user[_-]?([0-9a-f]{4,})`),          // user1234, user_1234, etc.
		regexp.MustCompile(`(?i)acc(oun)?t[_-]?([0-9a-f]{4,})`),    // account1234, acct_1234, etc.
		regexp.MustCompile(`(?i)subscr(iber)?[_-]?([0-9a-f]{4,})`), // subscriber1234, subscr_1234, etc.
		regexp.MustCompile(`(?i)cust(omer)?[_-]?([0-9a-f]{4,})`),   // customer1234, cust_1234, etc.
		regexp.MustCompile(`(?i)id[_-]?([0-9a-f]{6,})`),            // id123456, id_123456, etc.
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

			return anonID
		})
	}

	return result
}
