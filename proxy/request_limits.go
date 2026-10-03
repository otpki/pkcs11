package proxy

import "github.com/otpki/pkcs11/raw"

// validateRequestedOutput bounds sizes a caller can ask the native library to
// allocate directly. A small request must not be able to request gigabytes of
// random data or object handles. This is not a total process-memory budget,
// batches, decoded messages, and provider-sized outputs need separate limits.
func validateRequestedOutput(method string, arguments []any, maximum int) error {
	if maximum <= 0 {
		maximum = defaultMaximumMessageSize
	}
	// Leave space for the response envelope. Random bytes use base64 in JSON.
	payload := max(0, maximum-1024)
	var index, limit int
	switch method {
	case "GenerateRandom":
		index, limit = 1, payload/4*3
	case "FindObjects", "FindAllObjects":
		index, limit = 1, payload/256
		if method == "FindAllObjects" {
			index = 2
		}
	default:
		return nil
	}
	if len(arguments) <= index {
		return raw.Error(raw.CKR_ARGUMENTS_BAD)
	}
	count, ok := arguments[index].(int)
	if !ok {
		return raw.Error(raw.CKR_ARGUMENTS_BAD)
	}
	if method == "FindAllObjects" && count <= 0 {
		count = 64 // The raw helper uses this batch size when none is supplied.
	}
	if count < 0 || count > limit || (method == "FindObjects" && count == 0) {
		return raw.Error(raw.CKR_ARGUMENTS_BAD)
	}
	return nil
}
