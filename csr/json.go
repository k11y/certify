package csr

import (
	"cert-manager/certificates"
	"cert-manager/internal/utils"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
)

type CSRData struct {
	CertificateRequest CertificateRequest `json:"certificateRequest"`
}

type CertificateRequest struct {
	Data      CSRRequestData `json:"data"`
	Signature CSRSignature   `json:"signature"`
}

type CSRRequestData struct {
	Version       int                            `json:"version"`
	Subject       certificates.DistinguishedName `json:"subject"`
	SubjectPKInfo certificates.PublicKeyInfo     `json:"subjectPublicKeyInfo"`
	Attributes    []CSRAttribute                 `json:"attributes,omitempty"`
}

type CSRSignature struct {
	Algorithm string `json:"algorithm"`
	Signature string `json:"value"`
}

type CSRAttribute struct {
	Extensions map[string]interface{} `json:"requestedExtensions,omitempty"`
}

// MarshalToJSON converts CSR to JSON in OpenSSL format
func (c CSR) MarshalJSON() ([]byte, error) {
	csrData := CSRData{
		CertificateRequest: CertificateRequest{
			Data:      c.buildCSRData(),
			Signature: c.buildSignatureData(),
		},
	}

	return json.MarshalIndent(csrData, "", "    ")
}

// buildCSRData builds the main CSR data structure
func (c CSR) buildCSRData() CSRRequestData {
	return CSRRequestData{
		Version:       c.csr.Version,
		Subject:       certificates.BuildDistinguishedName(c.csr.Subject),
		SubjectPKInfo: certificates.BuildPublicKeyInfo(c.csr.PublicKeyAlgorithm, c.csr.PublicKey),
		Attributes:    c.buildAttributes(),
	}
}

// buildSignatureData builds signature information
func (c CSR) buildSignatureData() CSRSignature {
	return CSRSignature{
		Algorithm: c.csr.SignatureAlgorithm.String(),
		Signature: utils.FormatHexWithColons(hex.EncodeToString(c.csr.Signature)),
	}
}

// buildAttributes builds the requested extensions/attributes
func (c CSR) buildAttributes() []CSRAttribute {
	var attributes []CSRAttribute

	// Check if there are any extensions requested
	if len(c.csr.Extensions) > 0 {
		extensionMap := make(map[string]interface{})

		for _, ext := range c.csr.Extensions {
			extName := c.getExtensionName(ext.Id)

			switch {
			case ext.Id.Equal(certificates.OidExtensionSubjectAltName): // Subject Alternative Name
				san := certificates.SubjectAltName{
					DNSNames:       c.csr.DNSNames,
					EmailAddresses: c.csr.EmailAddresses,
				}
				for _, ip := range c.csr.IPAddresses {
					san.IPAddresses = append(san.IPAddresses, ip.String())
				}

				for _, uri := range c.csr.URIs {
					san.URIs = append(san.URIs, uri.String())
				}
				extensionMap[extName] = san

			case ext.Id.Equal(certificates.OidExtensionKeyUsage): // Key Usage
				keyUsage := c.parseKeyUsageExtension(ext.Value)
				if keyUsage != "" {
					extensionMap[extName] = keyUsage
				}

			case ext.Id.Equal(certificates.OidExtensionExtendedKeyUsage): // Extended Key Usage
				extKeyUsage := c.parseExtKeyUsageExtension(ext.Value)
				if len(extKeyUsage) > 0 {
					extensionMap[extName] = extKeyUsage
				}

			default:
				// For unknown extensions, show hex data
				extensionMap[extName] = utils.FormatHexWithColons(hex.EncodeToString(ext.Value))
			}
		}

		if len(extensionMap) > 0 {
			attributes = append(attributes, CSRAttribute{
				Extensions: extensionMap,
			})
		}
	}

	return attributes
}

// Helper functions for extension parsing
func (c CSR) getExtensionName(oid asn1.ObjectIdentifier) string {
	switch {
	case oid.Equal([]int{2, 5, 29, 17}):
		return "X509v3 Subject Alternative Name"
	case oid.Equal([]int{2, 5, 29, 15}):
		return "X509v3 Key Usage"
	case oid.Equal([]int{2, 5, 29, 37}):
		return "X509v3 Extended Key Usage"
	case oid.Equal([]int{2, 5, 29, 19}):
		return "X509v3 Basic Constraints"
	default:
		return fmt.Sprintf("Extension %s", oid.String())
	}
}

func (c CSR) parseKeyUsageExtension(data []byte) string {
	var keyUsage asn1.BitString
	if _, err := asn1.Unmarshal(data, &keyUsage); err != nil {
		return ""
	}

	var usages []string
	usage := keyUsage.Bytes[0]

	if usage&0x80 != 0 {
		usages = append(usages, "Digital Signature")
	}
	if usage&0x40 != 0 {
		usages = append(usages, "Non Repudiation")
	}
	if usage&0x20 != 0 {
		usages = append(usages, "Key Encipherment")
	}
	if usage&0x10 != 0 {
		usages = append(usages, "Data Encipherment")
	}
	if usage&0x08 != 0 {
		usages = append(usages, "Key Agreement")
	}
	if usage&0x04 != 0 {
		usages = append(usages, "Certificate Sign")
	}
	if usage&0x02 != 0 {
		usages = append(usages, "CRL Sign")
	}

	return strings.Join(usages, ", ")
}

func (c CSR) parseExtKeyUsageExtension(data []byte) []string {
	var oids []asn1.ObjectIdentifier
	if _, err := asn1.Unmarshal(data, &oids); err != nil {
		return nil
	}

	var usages []string
	for _, oid := range oids {
		switch {
		case oid.Equal([]int{1, 3, 6, 1, 5, 5, 7, 3, 1}):
			usages = append(usages, "TLS Web Server Authentication")
		case oid.Equal([]int{1, 3, 6, 1, 5, 5, 7, 3, 2}):
			usages = append(usages, "TLS Web Client Authentication")
		case oid.Equal([]int{1, 3, 6, 1, 5, 5, 7, 3, 3}):
			usages = append(usages, "Code Signing")
		case oid.Equal([]int{1, 3, 6, 1, 5, 5, 7, 3, 4}):
			usages = append(usages, "E-mail Protection")
		case oid.Equal([]int{1, 3, 6, 1, 5, 5, 7, 3, 8}):
			usages = append(usages, "Time Stamping")
		case oid.Equal([]int{1, 3, 6, 1, 5, 5, 7, 3, 9}):
			usages = append(usages, "OCSP Signing")
		default:
			usages = append(usages, oid.String())
		}
	}

	return usages
}
