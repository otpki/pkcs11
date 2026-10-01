package pkcs11

import "strings"

// normalizeAlias makes vendor catalog keys stable across packages and input
// sources. Vendor modules should use lowercase semantic names, but the driver
// normalizes defensively when a module is opened.
func normalizeAlias(name string) string { return strings.ToLower(strings.TrimSpace(name)) }

func cloneIDs(source map[string]NumericID) map[string]NumericID {
	if len(source) == 0 {
		return nil
	}
	result := make(map[string]NumericID, len(source))
	for name, value := range source {
		result[normalizeAlias(name)] = value
	}
	return result
}
