package securosys

const (
	// MechanismSKARSAPKCSKeyPairGen generates an RSA pair carrying Smart Key
	// Attribute authorization policies. Requires the vendor C_SKA* entry points.
	MechanismSKARSAPKCSKeyPairGen uint = 0x80002100
	// MechanismSKADSAKeyPairGen generates a DSA pair with SKA policies.
	MechanismSKADSAKeyPairGen uint = 0x80002101
	// MechanismSKAECKeyPairGen generates an EC pair with SKA policies.
	MechanismSKAECKeyPairGen uint = 0x80002102
	// MechanismSKAECEdwardsKeyPairGen generates an Edwards pair with SKA policies.
	MechanismSKAECEdwardsKeyPairGen uint = 0x80002103

	// MechanismRKSRSAKeyPairGen generates an RSA pair attestable against the
	// Securosys root CA. Requires the vendor C_RKSAttestKey entry point.
	MechanismRKSRSAKeyPairGen uint = 0x80002200
	// MechanismRKSECKeyPairGen generates an attestable EC pair.
	MechanismRKSECKeyPairGen uint = 0x80002201
)

const (
	// AttributeSKABlocked marks an object blocked by its SKA policy.
	AttributeSKABlocked uint = 0x80000001
	// AttributeSKASensitivePublicKey marks a public key as sensitive.
	AttributeSKASensitivePublicKey uint = 0x80000002
	// AttributeSKAUsageAccessBlob carries the SKA usage access blob.
	AttributeSKAUsageAccessBlob uint = 0x80000011
	// AttributeSKABlockAccessBlob carries the SKA block access blob.
	AttributeSKABlockAccessBlob uint = 0x80000012
	// AttributeSKAUnblockAccessBlob carries the SKA unblock access blob.
	AttributeSKAUnblockAccessBlob uint = 0x80000013
	// AttributeSKAModifyAccessBlob carries the SKA modify access blob.
	AttributeSKAModifyAccessBlob uint = 0x80000014
	// AttributeRKSAttestationSign requests an RKS attestation signature.
	AttributeRKSAttestationSign uint = 0x80000021
	// AttributeRKSCertificateChain carries the RKS attestation certificate chain.
	AttributeRKSCertificateChain uint = 0x80000022
)

// Securosys vendor return values occupy the 0x8nnnnnnn CKR_VENDOR_DEFINED space.
const (
	// ErrorWrongPIN reports a failed login with an invalid PKCS #11 PIN.
	ErrorWrongPIN uint = 0x8000000B
	// ErrorNotLoggedIn reports an operation that requires C_Login first.
	ErrorNotLoggedIn uint = 0x8000000C
	// ErrorHSMUnreachable reports that no HSM backing the slot is reachable. The
	// Primus cluster client may recover on a subsequent session.
	ErrorHSMUnreachable uint = 0x80005015
	// ErrorSetupPasswordLogin reports that permanent-secret bootstrap (ppin -a)
	// has not been completed for the connection.
	ErrorSetupPasswordLogin uint = 0x80005017
)
