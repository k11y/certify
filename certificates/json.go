package certificates

import (
	"cert-manager/internal/utils"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"time"
)

type CertificateJSON struct {
	Version              int                    `json:"version"`
	SerialNumber         string                 `json:"serialNumber"`
	Issuer               DistinguishedName      `json:"issuer"`
	Subject              DistinguishedName      `json:"subject"`
	Validity             Validity               `json:"validity"`
	SubjectPublicKeyInfo PublicKeyInfo          `json:"publicKeyInfo"`
	SignatureAlgorithm   string                 `json:"signatureAlgorithm"`
	Signature            string                 `json:"signature"`
	Extensions           map[string]interface{} `json:"requestedExtensions,omitempty"`
}

type Validity struct {
	NotBefore string `json:"notBefore"`
	NotAfter  string `json:"notAfter"`
}

type DistinguishedName struct {
	CommonName         string   `json:"commonName,omitempty"`
	Country            []string `json:"country,omitempty"`
	Organization       []string `json:"organization,omitempty"`
	OrganizationalUnit []string `json:"organizationalUnit,omitempty"`
	Locality           []string `json:"locality,omitempty"`
	Province           []string `json:"state,omitempty"`
	StreetAddress      []string `json:"streetAddress,omitempty"`
	PostalCode         []string `json:"postalCode,omitempty"`
	SerialNumber       string   `json:"serialNumber,omitempty"`
	EmailAddress       string   `json:"emailAddress,omitempty"`
	ExtraNames         []Name   `json:"extraNames,omitempty"`
}

type Name struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

type Extension struct {
	Critical bool `json:"critical"`
	Value    any  `json:"value"`
}

type SubjectAltName struct {
	DNSNames       []string `json:"dnsNames,omitempty"`
	EmailAddresses []string `json:"emailAddresses,omitempty"`
	IPAddresses    []string `json:"ipAddresses,omitempty"`
	URIs           []string `json:"uris,omitempty"`
}

type BasicConstraints struct {
	IsCA           bool `json:"isCA"`
	MaxPathLen     int  `json:"maxPathLen,omitempty"`
	MaxPathLenZero bool `json:"maxPathLenZero,omitempty"`
}

type AuthorityInfoAccess struct {
	OCSPServer            []string `json:"ocspServer,omitempty"`
	IssuingCertificateURL []string `json:"issuingCertificateURL,omitempty"`
}

type CertificatePolicy struct {
	Policy     string            `json:"policy"`
	Qualifiers []PolicyQualifier `json:"qualifiers,omitempty"`
}

type PolicyQualifier struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

type PolicyMapping struct {
	IssuerDomainPolicy  string `json:"issuerDomainPolicy"`
	SubjectDomainPolicy string `json:"subjectDomainPolicy"`
}

type NameConstraints struct {
	PermittedDNSDomains     []string `json:"permittedDNSDomains,omitempty"`
	ExcludedDNSDomains      []string `json:"excludedDNSDomains,omitempty"`
	PermittedIPRanges       []string `json:"permittedIPRanges,omitempty"`
	ExcludedIPRanges        []string `json:"excludedIPRanges,omitempty"`
	PermittedEmailAddresses []string `json:"permittedEmailAddresses,omitempty"`
	ExcludedEmailAddresses  []string `json:"excludedEmailAddresses,omitempty"`
	PermittedURIDomains     []string `json:"permittedURIDomains,omitempty"`
	ExcludedURIDomains      []string `json:"excludedURIDomains,omitempty"`
}

type PolicyConstraints struct {
	RequireExplicitPolicy int `json:"requireExplicitPolicy,omitempty"`
	InhibitPolicyMapping  int `json:"inhibitPolicyMapping,omitempty"`
}

type PublicKeyInfo struct {
	PublicKeyAlgorithm string     `json:"publicKeyAlgorithm"`
	PublicKey          *PublicKey `json:"publicKey,omitempty"`
}

type PublicKey struct {
	KeySize  string `json:"keySize"`
	Modulus  string `json:"modulus,omitempty"`
	Exponent string `json:"exponent,omitempty"`
	Pub      string `json:"pub,omitempty"`
	ASN1OID  string `json:"ASN1OID,omitempty"`
	NISTOID  string `json:"nistCurve,omitempty"`
}

func (c Certificate) MarshalJSON() ([]byte, error) {
	cert := c.certificate

	certJSON := CertificateJSON{
		Version:      cert.Version,
		SerialNumber: utils.FormatHexWithColons(cert.SerialNumber.Text(16)),
		Issuer:       BuildDistinguishedName(cert.Issuer),
		Subject:      BuildDistinguishedName(cert.Subject),
		Validity: Validity{
			NotBefore: cert.NotBefore.Format(time.RFC3339),
			NotAfter:  cert.NotAfter.Format(time.RFC3339),
		},
		SubjectPublicKeyInfo: BuildPublicKeyInfo(c.certificate.PublicKeyAlgorithm, c.certificate.PublicKey),
		SignatureAlgorithm:   cert.SignatureAlgorithm.String(),
		Signature:            utils.FormatHexWithColons(hex.EncodeToString(c.certificate.Signature)),
	}

	// Process specific extensions
	processExtensions(cert, &certJSON)

	return json.MarshalIndent(certJSON, "", "  ")
}

func getPublicKeySize(cert *x509.Certificate) int {
	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		return pub.N.BitLen()
	case *ecdsa.PublicKey:
		return pub.Curve.Params().BitSize
	default:
		return 0
	}
}

func processExtensions(cert *x509.Certificate, certJSON *CertificateJSON) {
	extensionMap := make(map[string]interface{})

	for _, ext := range cert.Extensions {
		switch {
		case ext.Id.Equal(OidExtensionKeyUsage):
			name, crit := GetExtensionName(OidExtensionKeyUsage)
			extensionMap[name] = Extension{
				Critical: crit,
				Value:    getKeyUsageStrings(cert.KeyUsage),
			}
		case ext.Id.Equal(OidExtensionExtendedKeyUsage):
			name, crit := GetExtensionName(OidExtensionExtendedKeyUsage)
			extensionMap[name] = Extension{
				Critical: crit,
				Value:    getExtKeyUsageStrings(cert.ExtKeyUsage),
			}
		case ext.Id.Equal(OidExtensionSubjectAltName):
			san := &SubjectAltName{
				DNSNames:       cert.DNSNames,
				EmailAddresses: cert.EmailAddresses,
			}

			for _, ip := range cert.IPAddresses {
				san.IPAddresses = append(san.IPAddresses, ip.String())
			}

			for _, uri := range cert.URIs {
				san.URIs = append(san.URIs, uri.String())
			}

			name, crit := GetExtensionName(OidExtensionSubjectAltName)
			extensionMap[name] = Extension{
				Critical: crit,
				Value:    san,
			}

		case ext.Id.Equal(OidExtensionBasicConstraints):
			name, crit := GetExtensionName(OidExtensionSubjectAltName)
			extensionMap[name] = Extension{
				Critical: crit,
				Value: &BasicConstraints{
					IsCA:           cert.IsCA,
					MaxPathLen:     cert.MaxPathLen,
					MaxPathLenZero: cert.MaxPathLenZero,
				},
			}
		case ext.Id.Equal(OidExtensionAuthorityKeyId):
			name, crit := GetExtensionName(OidExtensionAuthorityKeyId)
			extensionMap[name] = Extension{
				Critical: crit,
				Value:    fmt.Sprintf("%x", cert.AuthorityKeyId),
			}
		case ext.Id.Equal(OidExtensionSubjectKeyId):
			name, crit := GetExtensionName(OidExtensionSubjectKeyId)
			extensionMap[name] = Extension{
				Critical: crit,
				Value:    utils.FormatHexWithColons(fmt.Sprintf("%x", cert.SubjectKeyId)),
			}
		case ext.Id.Equal(OidExtensionCRLDistributionPoints):
			name, crit := GetExtensionName(OidExtensionCRLDistributionPoints)
			extensionMap[name] = Extension{
				Critical: crit,
				Value:    cert.CRLDistributionPoints,
			}
		case ext.Id.Equal(OidExtensionAuthorityInfoAccess):
			name, crit := GetExtensionName(OidExtensionAuthorityInfoAccess)
			extensionMap[name] = Extension{
				Critical: crit,
				Value: &AuthorityInfoAccess{
					OCSPServer:            cert.OCSPServer,
					IssuingCertificateURL: cert.IssuingCertificateURL,
				},
			}
		case ext.Id.Equal(OidExtensionCertificatePolicies):
			policies := make([]CertificatePolicy, 0, len(cert.PolicyIdentifiers))
			for _, oid := range cert.PolicyIdentifiers {
				policies = append(policies, CertificatePolicy{
					Policy: oid.String(),
				})
			}
			name, crit := GetExtensionName(OidExtensionCertificatePolicies)
			extensionMap[name] = Extension{
				Critical: crit,
				Value:    policies,
			}

		case ext.Id.Equal(OidExtensionIssuerAltName):
			// Parse Issuer Alternative Name
			if ian := parseSubjectAltName(ext.Value); ian != nil {
				name, crit := GetExtensionName(OidExtensionIssuerAltName)
				extensionMap[name] = Extension{
					Critical: crit,
					Value:    ian,
				}
			}
		case ext.Id.Equal(OidExtensionNameConstraints):
			// Parse Name Constraints
			nc := NameConstraints{
				PermittedDNSDomains:     cert.PermittedDNSDomains,
				PermittedURIDomains:     cert.PermittedURIDomains,
				PermittedEmailAddresses: cert.PermittedEmailAddresses,
				ExcludedDNSDomains:      cert.ExcludedDNSDomains,
				ExcludedURIDomains:      cert.ExcludedURIDomains,
				ExcludedEmailAddresses:  cert.ExcludedEmailAddresses,
			}

			for _, ip := range cert.PermittedIPRanges {
				nc.PermittedIPRanges = append(nc.PermittedIPRanges, ip.String())
			}

			for _, ip := range cert.ExcludedIPRanges {
				nc.ExcludedIPRanges = append(nc.ExcludedIPRanges, ip.String())
			}

			name, _ := GetExtensionName(OidExtensionNameConstraints)
			extensionMap[name] = Extension{
				Critical: cert.PermittedDNSDomainsCritical,
				Value:    nc,
			}

		case ext.Id.Equal(OidExtensionPolicyMappings):
			// Parse Policy Mappings
			pm := make([]PolicyMapping, 0)

			for _, v := range cert.PolicyMappings {
				pm = append(pm, PolicyMapping{IssuerDomainPolicy: v.IssuerDomainPolicy.String(), SubjectDomainPolicy: v.SubjectDomainPolicy.String()})
			}

			name, crit := GetExtensionName(OidExtensionPolicyMappings)
			extensionMap[name] = Extension{
				Critical: crit,
				Value:    pm,
			}
		case ext.Id.Equal(OidExtensionPolicyConstraints):
			// Parse Policy Constraints
			var pc PolicyConstraints
			valSet := false

			if cert.RequireExplicitPolicy > 0 || cert.RequireExplicitPolicyZero {
				pc.RequireExplicitPolicy = cert.RequireExplicitPolicy
				valSet = true
			}

			if cert.InhibitPolicyMapping > 0 || cert.InhibitPolicyMappingZero {
				pc.InhibitPolicyMapping = cert.InhibitPolicyMapping
				valSet = true
			}

			if valSet {
				name, crit := GetExtensionName(OidExtensionPolicyConstraints)
				extensionMap[name] = Extension{
					Critical: crit,
					Value:    pc,
				}
			}

		case ext.Id.Equal(OidExtensionInhibitAnyPolicy):
			// Parse Inhibit Any Policy
			if cert.InhibitAnyPolicy > 0 || cert.InhibitAnyPolicyZero {
				name, crit := GetExtensionName(OidExtensionInhibitAnyPolicy)
				extensionMap[name] = Extension{
					Critical: crit,
					Value:    cert.InhibitAnyPolicy,
				}
			}
		default:
			name, _ := GetExtensionName(OidExtensionFreshestCRL)
			if name == "" {
				name = ext.Id.String()
			}
			extensionMap[name] = Extension{
				Critical: ext.Critical,
				Value:    ext.Value,
			}
		}
	}
	certJSON.Extensions = extensionMap
}

func getKeyUsageStrings(usage x509.KeyUsage) []string {
	var usages []string

	if usage&x509.KeyUsageDigitalSignature != 0 {
		usages = append(usages, "Digital Signature")
	}
	if usage&x509.KeyUsageContentCommitment != 0 {
		usages = append(usages, "Content Commitment")
	}
	if usage&x509.KeyUsageKeyEncipherment != 0 {
		usages = append(usages, "Key Encipherment")
	}
	if usage&x509.KeyUsageDataEncipherment != 0 {
		usages = append(usages, "Data Encipherment")
	}
	if usage&x509.KeyUsageKeyAgreement != 0 {
		usages = append(usages, "Key Agreement")
	}
	if usage&x509.KeyUsageCertSign != 0 {
		usages = append(usages, "Certificate Sign")
	}
	if usage&x509.KeyUsageCRLSign != 0 {
		usages = append(usages, "CRL Sign")
	}
	if usage&x509.KeyUsageEncipherOnly != 0 {
		usages = append(usages, "Encipher Only")
	}
	if usage&x509.KeyUsageDecipherOnly != 0 {
		usages = append(usages, "Decipher Only")
	}

	return usages
}

func getExtKeyUsageStrings(usage []x509.ExtKeyUsage) []string {
	var usages []string

	for _, u := range usage {
		switch u {
		case x509.ExtKeyUsageAny:
			usages = append(usages, "Any")
		case x509.ExtKeyUsageServerAuth:
			usages = append(usages, "Server Authentication")
		case x509.ExtKeyUsageClientAuth:
			usages = append(usages, "Client Authentication")
		case x509.ExtKeyUsageCodeSigning:
			usages = append(usages, "Code Signing")
		case x509.ExtKeyUsageEmailProtection:
			usages = append(usages, "Email Protection")
		case x509.ExtKeyUsageIPSECEndSystem:
			usages = append(usages, "IPSEC End System")
		case x509.ExtKeyUsageIPSECTunnel:
			usages = append(usages, "IPSEC Tunnel")
		case x509.ExtKeyUsageIPSECUser:
			usages = append(usages, "IPSEC User")
		case x509.ExtKeyUsageTimeStamping:
			usages = append(usages, "Time Stamping")
		case x509.ExtKeyUsageOCSPSigning:
			usages = append(usages, "OCSP Signing")
		case x509.ExtKeyUsageMicrosoftServerGatedCrypto:
			usages = append(usages, "Microsoft Server Gated Crypto")
		case x509.ExtKeyUsageNetscapeServerGatedCrypto:
			usages = append(usages, "Netscape Server Gated Crypto")
		case x509.ExtKeyUsageMicrosoftCommercialCodeSigning:
			usages = append(usages, "Microsoft Commercial Code Signing")
		case x509.ExtKeyUsageMicrosoftKernelCodeSigning:
			usages = append(usages, "Microsoft Kernel Code Signing")
		}
	}

	return usages
}

func parseSubjectAltName(data []byte) *SubjectAltName {
	var sans SubjectAltName

	// Parse SAN extension
	var sanSequence asn1.RawValue
	if _, err := asn1.Unmarshal(data, &sanSequence); err != nil {
		return &sans
	}

	// Parse individual SAN entries
	rest := sanSequence.Bytes
	for len(rest) > 0 {
		var san asn1.RawValue
		var err error
		rest, err = asn1.Unmarshal(rest, &san)
		if err != nil {
			break
		}

		switch san.Tag {
		case 2: // dNSName
			sans.DNSNames = append(sans.DNSNames, fmt.Sprintf("DNS:%s", string(san.Bytes)))
		case 7: // iPAddress
			if len(san.Bytes) == 4 {
				ip := net.IP(san.Bytes)
				sans.IPAddresses = append(sans.IPAddresses, fmt.Sprintf("IP Address:%s", ip.String()))
			} else if len(san.Bytes) == 16 {
				ip := net.IP(san.Bytes)
				sans.IPAddresses = append(sans.IPAddresses, fmt.Sprintf("IP Address:%s", ip.String()))
			}
		case 6: // uniformResourceIdentifier
			sans.URIs = append(sans.URIs, fmt.Sprintf("URI:%s", string(san.Bytes)))
		case 1: // rfc822Name (email)
			sans.EmailAddresses = append(sans.EmailAddresses, fmt.Sprintf("email:%s", string(san.Bytes)))
		}
	}

	return &sans
}
