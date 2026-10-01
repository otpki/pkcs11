package proxy

import "github.com/otpki/pkcs11/raw"

type operationTransition uint8

const (
	operationStateless operationTransition = iota
	operationStart
	operationContinue
	operationFinish
)

type operationDescriptor struct {
	Name       string
	Transition operationTransition
	// Required lists every operation that must already be active on the same
	// physical session. It is used for dual-function update calls.
	Required []string
}

// allowsBeforeInitialize mirrors the narrow Cryptoki exception for interface
// discovery. All other public functions require a successful logical
// C_Initialize for this remote client instance.
func allowsBeforeInitialize(method string) bool {
	switch method {
	case methodDescribe, methodDestroy,
		"GetFunctionList", "GetInterfaceList", "GetInterface",
		"SetOutputBufferPolicy":
		return true
	default:
		return false
	}
}

// operationErrorKeepsState reports errors for which Cryptoki explicitly keeps
// the current operation available for a follow-up call. CKR_PENDING means the
// native provider is still executing. CKR_BUFFER_TOO_SMALL leaves variable-
// output operations active so the caller can retry with a larger buffer.
func operationErrorKeepsState(err error) bool {
	return raw.IsError(err, raw.CKR_PENDING) || raw.IsError(err, raw.CKR_BUFFER_TOO_SMALL)
}

func operationForMethod(method string) operationDescriptor {
	switch method {
	case "EncryptInit":
		return operationDescriptor{Name: "encrypt", Transition: operationStart}
	case "EncryptUpdate":
		return operationDescriptor{Name: "encrypt", Transition: operationContinue, Required: []string{"encrypt"}}
	case "Encrypt", "EncryptFinal":
		return operationDescriptor{Name: "encrypt", Transition: operationFinish, Required: []string{"encrypt"}}
	case "DecryptInit":
		return operationDescriptor{Name: "decrypt", Transition: operationStart}
	case "DecryptUpdate":
		return operationDescriptor{Name: "decrypt", Transition: operationContinue, Required: []string{"decrypt"}}
	case "Decrypt", "DecryptFinal":
		return operationDescriptor{Name: "decrypt", Transition: operationFinish, Required: []string{"decrypt"}}
	case "DigestInit":
		return operationDescriptor{Name: "digest", Transition: operationStart}
	case "DigestUpdate", "DigestKey":
		return operationDescriptor{Name: "digest", Transition: operationContinue, Required: []string{"digest"}}
	case "Digest", "DigestFinal":
		return operationDescriptor{Name: "digest", Transition: operationFinish, Required: []string{"digest"}}
	case "SignInit":
		return operationDescriptor{Name: "sign", Transition: operationStart}
	case "SignUpdate":
		return operationDescriptor{Name: "sign", Transition: operationContinue, Required: []string{"sign"}}
	case "Sign", "SignFinal":
		return operationDescriptor{Name: "sign", Transition: operationFinish, Required: []string{"sign"}}
	case "SignRecoverInit":
		return operationDescriptor{Name: "sign-recover", Transition: operationStart}
	case "SignRecover":
		return operationDescriptor{Name: "sign-recover", Transition: operationFinish, Required: []string{"sign-recover"}}
	case "VerifyInit":
		return operationDescriptor{Name: "verify", Transition: operationStart}
	case "VerifyUpdate":
		return operationDescriptor{Name: "verify", Transition: operationContinue, Required: []string{"verify"}}
	case "Verify", "VerifyFinal":
		return operationDescriptor{Name: "verify", Transition: operationFinish, Required: []string{"verify"}}
	case "VerifyRecoverInit":
		return operationDescriptor{Name: "verify-recover", Transition: operationStart}
	case "VerifyRecover":
		return operationDescriptor{Name: "verify-recover", Transition: operationFinish, Required: []string{"verify-recover"}}
	case "DigestEncryptUpdate":
		return operationDescriptor{Transition: operationContinue, Required: []string{"digest", "encrypt"}}
	case "DecryptDigestUpdate":
		return operationDescriptor{Transition: operationContinue, Required: []string{"decrypt", "digest"}}
	case "SignEncryptUpdate":
		return operationDescriptor{Transition: operationContinue, Required: []string{"sign", "encrypt"}}
	case "DecryptVerifyUpdate":
		return operationDescriptor{Transition: operationContinue, Required: []string{"decrypt", "verify"}}
	case "FindObjectsInit":
		return operationDescriptor{Name: "find", Transition: operationStart}
	case "FindObjects":
		return operationDescriptor{Name: "find", Transition: operationContinue, Required: []string{"find"}}
	case "FindObjectsFinal":
		return operationDescriptor{Name: "find", Transition: operationFinish, Required: []string{"find"}}

	// Message APIs initialize a process once, process one or more complete
	// messages, and terminate only at C_Message*Final. A one-shot C_*Message call
	// ends one message but deliberately keeps the process pinned for another.
	case "MessageEncryptInit":
		return operationDescriptor{Name: "message-encrypt", Transition: operationStart}
	case "EncryptMessage", "EncryptMessageBegin", "EncryptMessageNext":
		return operationDescriptor{Name: "message-encrypt", Transition: operationContinue, Required: []string{"message-encrypt"}}
	case "MessageEncryptFinal":
		return operationDescriptor{Name: "message-encrypt", Transition: operationFinish, Required: []string{"message-encrypt"}}
	case "MessageDecryptInit":
		return operationDescriptor{Name: "message-decrypt", Transition: operationStart}
	case "DecryptMessage", "DecryptMessageBegin", "DecryptMessageNext":
		return operationDescriptor{Name: "message-decrypt", Transition: operationContinue, Required: []string{"message-decrypt"}}
	case "MessageDecryptFinal":
		return operationDescriptor{Name: "message-decrypt", Transition: operationFinish, Required: []string{"message-decrypt"}}
	case "MessageSignInit":
		return operationDescriptor{Name: "message-sign", Transition: operationStart}
	case "SignMessage", "SignMessageBegin", "SignMessageNext":
		return operationDescriptor{Name: "message-sign", Transition: operationContinue, Required: []string{"message-sign"}}
	case "MessageSignFinal":
		return operationDescriptor{Name: "message-sign", Transition: operationFinish, Required: []string{"message-sign"}}
	case "MessageVerifyInit":
		return operationDescriptor{Name: "message-verify", Transition: operationStart}
	case "VerifyMessage", "VerifyMessageBegin", "VerifyMessageNext":
		return operationDescriptor{Name: "message-verify", Transition: operationContinue, Required: []string{"message-verify"}}
	case "MessageVerifyFinal":
		return operationDescriptor{Name: "message-verify", Transition: operationFinish, Required: []string{"message-verify"}}
	case "VerifySignatureInit":
		return operationDescriptor{Name: "signature-first-verify", Transition: operationStart}
	case "VerifySignatureUpdate":
		return operationDescriptor{Name: "signature-first-verify", Transition: operationContinue, Required: []string{"signature-first-verify"}}
	case "VerifySignature":
		return operationDescriptor{Name: "signature-first-verify", Transition: operationFinish, Required: []string{"signature-first-verify"}}
	case "VerifySignatureFinal":
		return operationDescriptor{Name: "signature-first-verify", Transition: operationFinish, Required: []string{"signature-first-verify"}}
	case "SetOperationState":
		return operationDescriptor{Name: "restored-operation", Transition: operationStart}
	}
	return operationDescriptor{}
}

func supportedCancelFlags() uint {
	return raw.CKF_FIND_OBJECTS | raw.CKF_ENCRYPT | raw.CKF_DECRYPT |
		raw.CKF_DIGEST | raw.CKF_SIGN | raw.CKF_SIGN_RECOVER |
		raw.CKF_VERIFY | raw.CKF_VERIFY_RECOVER |
		raw.CKF_MESSAGE_ENCRYPT | raw.CKF_MESSAGE_DECRYPT |
		raw.CKF_MESSAGE_SIGN | raw.CKF_MESSAGE_VERIFY
}

func operationsForCancelFlags(flags uint) []string {
	var names []string
	add := func(flag uint, values ...string) {
		if flags&flag != 0 {
			names = append(names, values...)
		}
	}
	add(raw.CKF_FIND_OBJECTS, "find")
	add(raw.CKF_ENCRYPT, "encrypt")
	add(raw.CKF_DECRYPT, "decrypt")
	add(raw.CKF_DIGEST, "digest")
	add(raw.CKF_SIGN, "sign")
	add(raw.CKF_SIGN_RECOVER, "sign-recover")
	add(raw.CKF_VERIFY, "verify", "signature-first-verify")
	add(raw.CKF_VERIFY_RECOVER, "verify-recover")
	add(raw.CKF_MESSAGE_ENCRYPT, "message-encrypt")
	add(raw.CKF_MESSAGE_DECRYPT, "message-decrypt")
	add(raw.CKF_MESSAGE_SIGN, "message-sign")
	add(raw.CKF_MESSAGE_VERIFY, "message-verify")
	return names
}

func cancelFlagsForOperations(operations map[string]bool) uint {
	var flags uint
	for name := range operations {
		switch name {
		case "find":
			flags |= raw.CKF_FIND_OBJECTS
		case "encrypt":
			flags |= raw.CKF_ENCRYPT
		case "decrypt":
			flags |= raw.CKF_DECRYPT
		case "digest":
			flags |= raw.CKF_DIGEST
		case "sign":
			flags |= raw.CKF_SIGN
		case "sign-recover":
			flags |= raw.CKF_SIGN_RECOVER
		case "verify", "signature-first-verify":
			flags |= raw.CKF_VERIFY
		case "verify-recover":
			flags |= raw.CKF_VERIFY_RECOVER
		case "message-encrypt":
			flags |= raw.CKF_MESSAGE_ENCRYPT
		case "message-decrypt":
			flags |= raw.CKF_MESSAGE_DECRYPT
		case "message-sign":
			flags |= raw.CKF_MESSAGE_SIGN
		case "message-verify":
			flags |= raw.CKF_MESSAGE_VERIFY
		case "restored-operation":
			// The serialized operation state does not identify its components.
			// Request every cancellable class so the native session is left clean.
			flags |= raw.CKF_FIND_OBJECTS | raw.CKF_ENCRYPT | raw.CKF_DECRYPT |
				raw.CKF_DIGEST | raw.CKF_SIGN | raw.CKF_SIGN_RECOVER |
				raw.CKF_VERIFY | raw.CKF_VERIFY_RECOVER |
				raw.CKF_MESSAGE_ENCRYPT | raw.CKF_MESSAGE_DECRYPT |
				raw.CKF_MESSAGE_SIGN | raw.CKF_MESSAGE_VERIFY
		}
	}
	return flags
}

func methodIdempotent(method string) bool {
	switch method {
	case methodDescribe, methodListRoutes,
		"GetInfo", "GetFunctionList", "GetInterface", "GetInterfaceList",
		"GetSlotList", "GetSlotInfo", "GetTokenInfo", "GetMechanismList", "GetMechanismInfo",
		"GetSessionInfo", "GetObjectSize", "GetAttributeValue", "GetSessionValidationFlags", "AsyncGetID":
		return true
	case "GenerateRandom":
		// Retrying with the same request ID returns the broker's cached response.
		// If the broker was never reached, producing a different random value is
		// still semantically equivalent for this API.
		return true
	default:
		return false
	}
}
