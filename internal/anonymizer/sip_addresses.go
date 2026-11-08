package anonymizer

import (
	"net"
	"net/netip"
	"strings"
)

// Address syntax is validated by netip; protocol fields determine its boundaries.
// Unknown headers are only inspected for explicit SIP URIs.
func anonymizeSIPAddresses(content string) (string, int, int) {
	v4, v6 := 0, 0
	address := func(value string) string {
		addr, err := netip.ParseAddr(value)
		if err != nil {
			return value
		}
		// Scoped addresses are not valid SIP/SDP address literals.
		if addr.Zone() != "" {
			return value
		}
		addr = addr.Unmap()
		ip := net.IP(addr.AsSlice())
		changed := false
		if addr.Is4() {
			changed = AnonymizeIPv4(ip)
		} else {
			changed = AnonymizeIPv6(ip)
		}
		if !changed {
			return value
		}
		if addr.Is4() {
			v4++
		} else {
			v6++
		}
		return ip.String()
	}
	host := func(value string) string { return replaceSIPHost(value, address) }
	lines := strings.SplitAfter(content, "\n")
	inBody := false
	for i, line := range lines {
		if strings.TrimSpace(line) == "" {
			inBody = true
			continue
		}
		if inBody || strings.HasPrefix(line, "c=") || strings.HasPrefix(line, "o=") || strings.HasPrefix(line, "a=") {
			lines[i] = replaceSDPAddresses(line, address)
			continue
		}
		// URIs may occur in the request line, standard headers and extension headers.
		line = replaceSIPURIs(line, host)
		colon := strings.IndexByte(line, ':')
		if colon < 0 {
			lines[i] = line
			continue
		}
		name := strings.ToLower(strings.TrimSpace(line[:colon]))
		value := line[colon+1:]
		switch name {
		case "via", "v":
			parts := strings.Split(value, ",")
			for j, part := range parts {
				parts[j] = replaceField(part, 1, host)
				params := strings.Split(parts[j], ";")
				for k := 1; k < len(params); k++ {
					key, val, ok := strings.Cut(params[k], "=")
					if ok && (strings.EqualFold(strings.TrimSpace(key), "received") || strings.EqualFold(strings.TrimSpace(key), "maddr")) {
						params[k] = key + "=" + replaceField(val, 0, host)
					}
				}
				parts[j] = strings.Join(params, ";")
			}
			value = strings.Join(parts, ",")
		case "call-id", "i":
			if at := strings.LastIndexByte(value, '@'); at >= 0 {
				value = value[:at+1] + replaceField(value[at+1:], 0, host)
			}
		case "x-forwarded-for", "x-real-ip":
			parts := strings.Split(value, ",")
			for j := range parts {
				parts[j] = replaceField(parts[j], 0, host)
			}
			value = strings.Join(parts, ",")
		}
		lines[i] = line[:colon+1] + value
	}
	return strings.Join(lines, ""), v4, v6
}

// replaceField preserves whitespace and replaces one whitespace-delimited field.
func replaceField(text string, index int, replace func(string) string) string {
	fields := strings.Fields(text)
	if index < 0 || index >= len(fields) {
		return text
	}
	pos := 0
	for i, field := range fields {
		start := pos + strings.Index(text[pos:], field)
		if i == index {
			return text[:start] + replace(field) + text[start+len(field):]
		}
		pos = start + len(field)
	}
	return text
}

func replaceSIPHost(value string, address func(string) string) string {
	// URI parameters follow the host and must not be parsed as part of an address.
	end := strings.IndexAny(value, ";?")
	if end < 0 {
		end = len(value)
	}
	endpoint, suffix := value[:end], value[end:]
	if strings.HasPrefix(endpoint, "[") {
		if close := strings.IndexByte(endpoint, ']'); close >= 0 {
			return "[" + address(endpoint[1:close]) + "]" + endpoint[close+1:] + suffix
		}
		return value
	}
	// Parse the entire literal first: an unbracketed IPv6 must not lose its tail.
	if _, err := netip.ParseAddr(endpoint); err == nil {
		return address(endpoint) + suffix
	}
	if h, p, err := net.SplitHostPort(endpoint); err == nil {
		return address(h) + ":" + p + suffix
	}
	return value
}

func replaceSIPURIs(text string, host func(string) string) string {
	var out strings.Builder
	for offset := 0; offset < len(text); {
		lower := strings.ToLower(text[offset:])
		start := strings.Index(lower, "sip:")
		secure := strings.Index(lower, "sips:")
		scheme := 4
		if secure >= 0 && (start < 0 || secure < start) {
			start = secure
			scheme = 5
		}
		if start < 0 {
			out.WriteString(text[offset:])
			break
		}
		start += offset
		begin := start + scheme
		end := begin
		for end < len(text) && !strings.ContainsRune(" \t\r\n<>\"", rune(text[end])) {
			end++
		}
		authority := text[begin:end]
		hostStart := 0
		if at := strings.LastIndexByte(authority, '@'); at >= 0 {
			hostStart = at + 1
		}
		out.WriteString(text[offset : begin+hostStart])
		out.WriteString(host(authority[hostStart:]))
		offset = end
	}
	return out.String()
}

func replaceSDPAddresses(line string, address func(string) string) string {
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return line
	}
	// Connection addresses may include multicast TTL/address-count suffixes.
	connection := func(value string) string {
		ip, suffix, ok := strings.Cut(value, "/")
		if ok {
			return address(ip) + "/" + suffix
		}
		return address(value)
	}
	switch {
	case fields[0] == "c=IN" && len(fields) == 3 && (fields[1] == "IP4" || fields[1] == "IP6"):
		return replaceField(line, 2, connection)
	case strings.HasPrefix(fields[0], "o=") && len(fields) == 6 && fields[3] == "IN":
		return replaceField(line, 5, address)
	case strings.HasPrefix(fields[0], "a=rtcp:") && len(fields) == 4 && fields[1] == "IN":
		return replaceField(line, 3, address)
	case strings.HasPrefix(fields[0], "a=candidate:") && len(fields) >= 8:
		line = replaceField(line, 4, address)
		for i := 8; i+1 < len(fields); i++ {
			if fields[i] == "raddr" {
				line = replaceField(line, i+1, address)
			}
		}
	}
	return line
}
