package pkcs11

import (
	"context"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"

	"github.com/otpki/pkcs11/raw"
)

// CertificateImportOptions controls creation of a CKO_CERTIFICATE object.
// The default object is a public, modifiable token object. Trusted is omitted
// unless explicitly set because many modules restrict CKA_TRUSTED to an SO.
type CertificateImportOptions struct {
	// Label becomes CKA_LABEL when non-empty.
	Label string
	// ID becomes CKA_ID and should normally equal the associated key's CKA_ID.
	ID []byte

	// Token controls CKA_TOKEN. Nil defaults to true.
	Token *bool
	// Private controls CKA_PRIVATE. Nil defaults to false.
	Private *bool
	// Trusted controls CKA_TRUSTED. Nil omits the attribute entirely because many
	// providers permit only a security officer to set it.
	Trusted *bool
	// Modifiable controls CKA_MODIFIABLE. Nil defaults to true.
	Modifiable *bool
	// Copyable controls CKA_COPYABLE. Nil defaults to true.
	Copyable *bool
	// Destroyable controls CKA_DESTROYABLE. Nil defaults to true.
	Destroyable *bool

	// ReplaceExisting destroys existing X.509 certificate objects selected by
	// ID (preferred) or Label before creating the new object. Replacement is not
	// atomic: a later create failure can leave the old object removed.
	ReplaceExisting bool
	// Attributes are merged last and may add provider-specific metadata, but may
	// not override the object class, certificate type, or DER value.
	Attributes []*raw.Attribute
	// TemplatePolicy can apply deployment-wide attribute policy before Attributes.
	TemplatePolicy TemplatePolicy
}

// CertificateQuery locates X.509 certificate objects by their conventional
// CKA_UNIQUE_ID, CKA_LABEL, or CKA_ID. A zero query returns all X.509 certificates.
type CertificateQuery struct {
	// UniqueID matches CKA_UNIQUE_ID when supported by the provider.
	UniqueID string
	// Label matches CKA_LABEL.
	Label string
	// ID matches CKA_ID and is usually the associated key identifier.
	ID []byte
	// Limit bounds returned results after the token search. Zero means unlimited.
	Limit int
}

// CertificateRef is a certificate object together with its parsed X.509 value.
type CertificateRef struct {
	// Object is the token object reference used for later mutation or deletion.
	Object ObjectRef
	// Certificate is the parsed value of CKA_VALUE.
	Certificate *x509.Certificate
}

func boolValue(value *bool, fallback bool) bool {
	if value == nil {
		return fallback
	}
	return *value
}

// certificateSerialDER preserves the ASN.1 INTEGER encoding required by
// CKA_SERIAL_NUMBER, including any leading sign-protection octet.
func certificateSerialDER(cert *x509.Certificate) ([]byte, error) {
	if cert == nil || cert.SerialNumber == nil {
		return nil, fmt.Errorf("pkcs11: X.509 certificate serial number is required")
	}
	encoded, err := asn1.Marshal(cert.SerialNumber)
	if err != nil {
		return nil, fmt.Errorf("pkcs11: encode certificate serial number: %w", err)
	}
	return encoded, nil
}

func certificateTemplate(cert *x509.Certificate, options CertificateImportOptions) ([]*raw.Attribute, error) {
	if cert == nil || len(cert.Raw) == 0 {
		return nil, fmt.Errorf("pkcs11: parsed X.509 certificate with DER value is required")
	}
	serial, err := certificateSerialDER(cert)
	if err != nil {
		return nil, err
	}
	attributes := []*raw.Attribute{
		raw.NewAttribute(raw.CKA_CLASS, raw.CKO_CERTIFICATE),
		raw.NewAttribute(raw.CKA_CERTIFICATE_TYPE, raw.CKC_X_509),
		raw.NewAttribute(raw.CKA_TOKEN, boolValue(options.Token, true)),
		raw.NewAttribute(raw.CKA_PRIVATE, boolValue(options.Private, false)),
		raw.NewAttribute(raw.CKA_MODIFIABLE, boolValue(options.Modifiable, true)),
		raw.NewAttribute(raw.CKA_COPYABLE, boolValue(options.Copyable, true)),
		raw.NewAttribute(raw.CKA_DESTROYABLE, boolValue(options.Destroyable, true)),
		raw.NewAttribute(raw.CKA_SUBJECT, cert.RawSubject),
		raw.NewAttribute(raw.CKA_ISSUER, cert.RawIssuer),
		raw.NewAttribute(raw.CKA_SERIAL_NUMBER, serial),
		raw.NewAttribute(raw.CKA_VALUE, cert.Raw),
	}
	if options.Label != "" {
		attributes = append(attributes, raw.NewAttribute(raw.CKA_LABEL, options.Label))
	}
	if options.ID != nil {
		attributes = append(attributes, raw.NewAttribute(raw.CKA_ID, options.ID))
	}
	if options.Trusted != nil {
		attributes = append(attributes, raw.NewAttribute(raw.CKA_TRUSTED, *options.Trusted))
	}
	if len(cert.RawSubjectPublicKeyInfo) != 0 {
		attributes = append(attributes, raw.NewAttribute(raw.CKA_PUBLIC_KEY_INFO, cert.RawSubjectPublicKeyInfo))
	}
	attributes, err = applyTemplatePolicy(options.TemplatePolicy, TemplateContext{
		Operation:   Operation("import-certificate"),
		ObjectClass: raw.CKO_CERTIFICATE,
		Label:       options.Label,
		ID:          options.ID,
	}, attributes)
	if err != nil {
		return nil, err
	}
	attributes = mergeAttributes(attributes, options.Attributes)
	if err := validateCertificateInvariants(attributes, cert.Raw); err != nil {
		return nil, err
	}
	return attributes, nil
}

func validateCertificateInvariants(attributes []*raw.Attribute, certificateDER []byte) error {
	for _, attribute := range attributes {
		if attribute == nil {
			continue
		}
		switch attribute.Type {
		case raw.CKA_CLASS:
			value, ok := raw.ULong(attribute.Value)
			if !ok || value != raw.CKO_CERTIFICATE {
				return fmt.Errorf("pkcs11: certificate template overrides CKA_CLASS")
			}
		case raw.CKA_CERTIFICATE_TYPE:
			value, ok := raw.ULong(attribute.Value)
			if !ok || value != raw.CKC_X_509 {
				return fmt.Errorf("pkcs11: certificate template overrides CKA_CERTIFICATE_TYPE")
			}
		case raw.CKA_VALUE:
			if string(attribute.Value) != string(certificateDER) {
				return fmt.Errorf("pkcs11: certificate template overrides CKA_VALUE")
			}
		}
	}
	return nil
}

func certificateQueryTemplate(query CertificateQuery) []*raw.Attribute {
	attributes := []*raw.Attribute{
		raw.NewAttribute(raw.CKA_CLASS, raw.CKO_CERTIFICATE),
		raw.NewAttribute(raw.CKA_CERTIFICATE_TYPE, raw.CKC_X_509),
	}
	if query.UniqueID != "" {
		attributes = append(attributes, raw.NewAttribute(raw.CKA_UNIQUE_ID, query.UniqueID))
	}
	if query.Label != "" {
		attributes = append(attributes, raw.NewAttribute(raw.CKA_LABEL, query.Label))
	}
	if query.ID != nil {
		attributes = append(attributes, raw.NewAttribute(raw.CKA_ID, query.ID))
	}
	return attributes
}

// ImportCertificate creates an X.509 certificate object and returns its object
// reference. Set ID to the associated key's CKA_ID for portable key/certificate
// association across PKCS #11 implementations.
func (c *Client) ImportCertificate(ctx context.Context, cert *x509.Certificate, options CertificateImportOptions) (CertificateRef, error) {
	attributes, err := certificateTemplate(cert, options)
	if err != nil {
		return CertificateRef{}, err
	}
	var handle raw.ObjectHandle
	err = c.withSession(ctx, sessionOptions{Operation: "import-certificate", ReadWrite: true}, func(session *sessionLease) error {
		if options.ReplaceExisting {
			// Search and deletion occur in the same managed read/write session. PKCS #11
			// has no portable transaction primitive, so replacement remains best effort.
			if options.ID == nil && options.Label == "" {
				return fmt.Errorf("pkcs11: ReplaceExisting requires certificate ID or label")
			}
			handles, findErr := session.FindAllObjects(certificateQueryTemplate(CertificateQuery{Label: options.Label, ID: options.ID}), 64)
			if findErr != nil {
				return findErr
			}
			for _, existing := range handles {
				if destroyErr := session.DestroyObject(existing); destroyErr != nil {
					return fmt.Errorf("pkcs11: replace certificate object 0x%x: %w", uint(existing), destroyErr)
				}
			}
		}
		handle, err = session.CreateObject(attributes)
		return err
	})
	if err != nil {
		return CertificateRef{}, err
	}
	return CertificateRef{
		Object:      ObjectRef{Handle: handle, Class: raw.CKO_CERTIFICATE, Label: options.Label, ID: append([]byte(nil), options.ID...)},
		Certificate: cert,
	}, nil
}

// ImportCertificateForKey applies the key's CKA_ID, and its label when no
// certificate label was supplied, before importing the certificate.
func (c *Client) ImportCertificateForKey(ctx context.Context, cert *x509.Certificate, key ObjectRef, options CertificateImportOptions) (CertificateRef, error) {
	if options.ID == nil {
		options.ID = append([]byte(nil), key.ID...)
	}
	if options.Label == "" {
		options.Label = key.Label
	}
	return c.ImportCertificate(ctx, cert, options)
}

// FindCertificates returns parsed X.509 certificate objects. Attribute query
// errors are joined with parse errors while preserving any successfully read
// certificates.
func (c *Client) FindCertificates(ctx context.Context, query CertificateQuery) ([]CertificateRef, error) {
	var result []CertificateRef
	var collected []error
	err := c.withSession(ctx, sessionOptions{Operation: "find-certificates", Idempotent: true}, func(session *sessionLease) error {
		handles, findErr := session.FindAllObjects(certificateQueryTemplate(query), 64)
		if findErr != nil {
			return findErr
		}
		if query.Limit > 0 && len(handles) > query.Limit {
			handles = handles[:query.Limit]
		}
		for _, handle := range handles {
			// Keep portable certificate attributes in one query. CKA_UNIQUE_ID was
			// added after the original certificate object model and is still rejected
			// by otherwise conforming modules, including SoftHSM 2. Querying it with
			// CKA_VALUE can make those modules reject the entire request.
			attributes, attributeErr := session.GetAttributeValue(handle, []*raw.Attribute{
				raw.NewAttribute(raw.CKA_LABEL, nil),
				raw.NewAttribute(raw.CKA_ID, nil),
				raw.NewAttribute(raw.CKA_VALUE, nil),
			})
			if attributeErr != nil && len(attributes) == 0 {
				collected = append(collected, fmt.Errorf("certificate object 0x%x: %w", uint(handle), attributeErr))
				continue
			}
			object := ObjectRef{Handle: handle, Class: raw.CKO_CERTIFICATE}
			var value []byte
			for _, attribute := range attributes {
				switch attribute.Type {
				case raw.CKA_LABEL:
					object.Label = string(attribute.Value)
				case raw.CKA_ID:
					object.ID = append([]byte(nil), attribute.Value...)
				case raw.CKA_VALUE:
					value = append([]byte(nil), attribute.Value...)
				}
			}

			// CKA_UNIQUE_ID is useful durable metadata, but it is optional for
			// compatibility. Ignore only CKR_ATTRIBUTE_TYPE_INVALID; transport,
			// session, and other operational errors still belong in the result.
			uniqueAttributes, uniqueErr := session.GetAttributeValue(handle, []*raw.Attribute{
				raw.NewAttribute(raw.CKA_UNIQUE_ID, nil),
			})
			if len(uniqueAttributes) == 1 && uniqueAttributes[0] != nil {
				object.UniqueID = string(uniqueAttributes[0].Value)
			}
			if uniqueErr != nil && !raw.IsError(uniqueErr, raw.CKR_ATTRIBUTE_TYPE_INVALID) {
				collected = append(collected, fmt.Errorf("certificate object 0x%x CKA_UNIQUE_ID: %w", uint(handle), uniqueErr))
			}

			cert, parseErr := x509.ParseCertificate(value)
			if parseErr != nil {
				collected = append(collected, fmt.Errorf("certificate object 0x%x: parse CKA_VALUE: %w", uint(handle), parseErr))
				continue
			}
			result = append(result, CertificateRef{Object: object, Certificate: cert})
			if attributeErr != nil {
				collected = append(collected, fmt.Errorf("certificate object 0x%x: %w", uint(handle), attributeErr))
			}
		}
		return nil
	})
	return result, errors.Join(err, errors.Join(collected...))
}

// FindCertificateForKey resolves exactly one certificate by the key's CKA_ID.
func (c *Client) FindCertificateForKey(ctx context.Context, key ObjectRef) (CertificateRef, error) {
	if key.ID == nil {
		return CertificateRef{}, fmt.Errorf("pkcs11: key has no CKA_ID")
	}
	certificates, err := c.FindCertificates(ctx, CertificateQuery{ID: key.ID, Limit: 2})
	if err != nil && len(certificates) == 0 {
		return CertificateRef{}, err
	}
	if len(certificates) == 0 {
		return CertificateRef{}, fmt.Errorf("pkcs11: no certificate matches key CKA_ID")
	}
	if len(certificates) > 1 {
		return CertificateRef{}, fmt.Errorf("pkcs11: %d certificates match key CKA_ID", len(certificates))
	}
	return certificates[0], err
}
