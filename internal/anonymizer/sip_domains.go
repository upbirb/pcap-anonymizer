package anonymizer

import (
	"fmt"
	"strings"
)

var (
	sipDomainMap            = make(map[string]string)
	sipDomainAliases        = make(map[string]struct{})
	nextDomainID     uint64 = 1
)

// URI hostname comparison is case-insensitive. A final root dot is retained in
// output, but is not part of the mapping key. No DNS lookup is performed.
func anonymizeSIPDomain(host string) string {
	canonical := strings.ToLower(strings.TrimSuffix(host, "."))
	if !isSIPHostname(canonical) {
		return host
	}
	suffix := ""
	if strings.HasSuffix(host, ".") {
		suffix = "."
	}
	mapMutex.Lock()
	defer mapMutex.Unlock()
	if replacement, ok := sipDomainMap[canonical]; ok {
		return replacement + suffix
	}
	if _, ok := sipDomainAliases[canonical]; ok {
		return host
	}
	var replacement string
	for {
		replacement = fmt.Sprintf("domain-%d.invalid", nextDomainID)
		nextDomainID++
		if replacement == canonical {
			continue
		}
		if _, used := sipDomainMap[replacement]; !used {
			break
		}
	}
	sipDomainMap[canonical] = replacement
	sipDomainAliases[replacement] = struct{}{}
	return replacement + suffix
}

// SIP hostnames use ASCII DNS labels, including IDNA names in punycode form.
// A numeric final label is not a hostname; invalid IP literals must not silently
// turn into domain aliases after IP parsing fails.
func isSIPHostname(host string) bool {
	if len(host) == 0 || len(host) > 253 {
		return false
	}
	labels := strings.Split(host, ".")
	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	top := labels[len(labels)-1]
	return top[0] >= 'a' && top[0] <= 'z'
}

func GetSIPDomainMappingStats() int {
	mapMutex.RLock()
	defer mapMutex.RUnlock()
	return len(sipDomainMap)
}

// GetSampleSIPDomainMappings contains original identities; expose it only after
// an explicit request for mappings, never in default or verbose diagnostics.
func GetSampleSIPDomainMappings(count int) map[string]string {
	mapMutex.RLock()
	defer mapMutex.RUnlock()
	result := make(map[string]string)
	for original, replacement := range sipDomainMap {
		if len(result) >= count {
			break
		}
		result[original] = replacement
	}
	return result
}
