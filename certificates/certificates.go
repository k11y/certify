package certificates

import (
	"cert-manager/internal/utils"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"strings"
)

// Certificate struct
// Parse certificate
// Print cert - json and human readable

type Certificate struct {
	certificate *x509.Certificate
}

func ParseCertificate(certBytes []byte) (Certificate, error) {
	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return Certificate{}, err
	}

	return Certificate{certificate: cert}, nil
}

// PrintCertificate prints certificate in OpenSSL format
func (c Certificate) PrintCertificate() (string, error) {
	var sb strings.Builder

	sb.WriteString("Certificate:\n")
	sb.WriteString("    Data:\n")

	// Version
	sb.WriteString(fmt.Sprintf("        Version: %d (0x%x)\n", c.certificate.Version, c.certificate.Version-1))

	// Serial Number
	serialHex := strings.ToLower(c.certificate.SerialNumber.Text(16))
	if len(serialHex)%2 != 0 {
		serialHex = "0" + serialHex
	}
	sb.WriteString(fmt.Sprintf("        Serial Number:\n"))
	sb.WriteString(fmt.Sprintf("            %s\n", utils.FormatHexWithColons(serialHex)))

	// Signature Algorithm
	sb.WriteString(fmt.Sprintf("        Signature Algorithm: %s\n", c.certificate.SignatureAlgorithm.String()))

	// Issuer
	sb.WriteString(fmt.Sprintf("        Issuer: %s\n", c.certificate.Issuer.String()))

	// Validity
	sb.WriteString("        Validity\n")
	sb.WriteString(fmt.Sprintf("            Not Before: %s\n", c.certificate.NotBefore.Format("Jan 2 15:04:05 2006 MST")))
	sb.WriteString(fmt.Sprintf("            Not After : %s\n", c.certificate.NotAfter.Format("Jan 2 15:04:05 2006 MST")))

	// Subject
	sb.WriteString(fmt.Sprintf("        Subject: %s\n", c.certificate.Subject.String()))

	// Public Key Info
	pkInfo, err := GetPublicKeyInfo(c.certificate.PublicKeyAlgorithm.String(), c.certificate.PublicKey)
	if err != nil {
		return "", err
	}
	sb.WriteString(pkInfo)

	// Extensions
	if len(c.certificate.Extensions) > 0 {
		sb.WriteString("        X509v3 extensions:\n")
		sb.WriteString(c.formatExtensions())
	}

	// Signature Algorithm (repeated)
	sb.WriteString(fmt.Sprintf("    Signature Algorithm: %s\n", c.certificate.SignatureAlgorithm.String()))

	// Signature
	signature := hex.EncodeToString(c.certificate.Signature)
	sb.WriteString(utils.FormatHexBlock(signature, 7) + "\n")

	return sb.String(), nil
}

// getPublicKeyInfo extracts and formats public key information
func GetPublicKeyInfo(algorithm string, publicKey any) (string, error) {
	var sb strings.Builder

	sb.WriteString("        Subject Public Key Info:\n")
	sb.WriteString(fmt.Sprintf("            Public Key Algorithm: %s\n", algorithm))

	switch pub := publicKey.(type) {
	case *rsa.PublicKey:
		sb.WriteString(fmt.Sprintf("                RSA Public-Key: (%d bit)\n", pub.N.BitLen()))
		sb.WriteString("                Modulus:\n")
		modulus := pub.N.Bytes()
		sb.WriteString(utils.FormatHexBlock(hex.EncodeToString(modulus), 20))
		sb.WriteString(fmt.Sprintf("\n                Exponent: %d (0x%x)\n", pub.E, pub.E))

	case *ecdsa.PublicKey:
		sb.WriteString(fmt.Sprintf("                Public-Key: (%d bit)\n", pub.Curve.Params().BitSize))
		sb.WriteString("                pub:\n")
		x := pub.X.Bytes()
		y := pub.Y.Bytes()

		// Pad to ensure correct length
		fieldSize := (pub.Curve.Params().BitSize + 7) / 8
		if len(x) < fieldSize {
			padding := make([]byte, fieldSize-len(x))
			x = append(padding, x...)
		}
		if len(y) < fieldSize {
			padding := make([]byte, fieldSize-len(y))
			y = append(padding, y...)
		}

		pubKeyBytes := append([]byte{0x04}, append(x, y...)...)
		sb.WriteString(utils.FormatHexBlock(hex.EncodeToString(pubKeyBytes), 20))
		sb.WriteString(fmt.Sprintf("\n                ASN1 OID: %s\n", pub.Curve.Params().Name))

	case ed25519.PublicKey:
		sb.WriteString("                ED25519 Public-Key:\n")
		sb.WriteString("                pub:\n")
		sb.WriteString(utils.FormatHexBlock(hex.EncodeToString(pub), 20))

	default:
		sb.WriteString("                Unknown Public Key Type\n")
	}

	return sb.String(), nil
}

// formatExtensions formats certificate extensions

func (c Certificate) formatExtensions() string {
	var sb strings.Builder

	// Process all extensions in order
	for _, ext := range c.certificate.Extensions {
		extName, critical := GetExtensionName(ext.Id)

		if critical && ext.Critical {
			sb.WriteString(fmt.Sprintf("            %s: critical\n", extName))
		} else {
			sb.WriteString(fmt.Sprintf("            %s:\n", extName))
		}

		switch {
		// Subject Key Identifier
		case ext.Id.Equal(OidExtensionSubjectKeyId):
			ski := FormatSubjectKeyIdentifier(ext.Value)
			sb.WriteString(fmt.Sprintf("                %s\n", ski))

		// Authority Key Identifier
		case ext.Id.Equal(OidExtensionAuthorityKeyId):
			aki := FormatAuthorityKeyIdentifier(ext.Value)
			sb.WriteString(fmt.Sprintf("                %s\n", aki))

		// Key Usage
		case ext.Id.Equal(OidExtensionKeyUsage):
			usage := FormatKeyUsage(c.certificate.KeyUsage)
			sb.WriteString(fmt.Sprintf("                %s\n", usage))

		// Extended Key Usage
		case ext.Id.Equal(OidExtensionExtendedKeyUsage):
			extUsage := FormatExtendedKeyUsage(c.certificate.ExtKeyUsage)
			sb.WriteString(fmt.Sprintf("                %s\n", extUsage))

		// Basic Constraints
		case ext.Id.Equal(OidExtensionBasicConstraints):
			basicConstraints := FormatBasicConstraints(c.certificate)
			sb.WriteString(fmt.Sprintf("                %s\n", basicConstraints))

		// Subject Alternative Name
		case ext.Id.Equal(OidExtensionSubjectAltName):
			san := FormatSubjectAlternativeName(c.certificate.DNSNames, c.certificate.IPAddresses, c.certificate.EmailAddresses, c.certificate.URIs)
			sb.WriteString(fmt.Sprintf("                %s\n", san))

		// Issuer Alternative Name
		case ext.Id.Equal(OidExtensionIssuerAltName):
			ian := FormatIssuerAlternativeName(ext.Value)
			sb.WriteString(fmt.Sprintf("                %s\n", ian))

		// Certificate Policies
		case ext.Id.Equal(OidExtensionCertificatePolicies):
			policies := FormatCertificatePolicies(ext.Value)
			sb.WriteString(fmt.Sprintf("                %s\n", policies))

		// CRL Distribution Points
		case ext.Id.Equal(OidExtensionCRLDistributionPoints):
			crl := FormatCRLDistributionPoints(ext.Value)
			sb.WriteString(fmt.Sprintf("                %s\n", crl))

		// Authority Information Access
		case ext.Id.Equal(OidExtensionAuthorityInfoAccess):
			aia := FormatAuthorityInfoAccess(ext.Value)
			sb.WriteString(fmt.Sprintf("                %s\n", aia))

		// Name Constraints
		case ext.Id.Equal(OidExtensionNameConstraints):
			nameConstraints := FormatNameConstraints(c.certificate)
			sb.WriteString(fmt.Sprintf("                %s\n", nameConstraints))

		// Policy Constraints
		case ext.Id.Equal(OidExtensionPolicyConstraints):
			policyConstraints := FormatPolicyConstraints(c.certificate)
			sb.WriteString(fmt.Sprintf("                %s\n", policyConstraints))

		// Inhibit Any Policy
		case ext.Id.Equal(OidExtensionInhibitAnyPolicy):
			inhibit := FormatInhibitAnyPolicy(ext.Value)
			sb.WriteString(fmt.Sprintf("                %s\n", inhibit))

		// Policy Mappings
		case ext.Id.Equal(OidExtensionPolicyMappings):
			mappings := FormatPolicyMappings(c.certificate)
			sb.WriteString(fmt.Sprintf("                %s\n", mappings))

		// CT Precertificate SCTs
		case ext.Id.Equal(OidExtensionPrecertificateSCT):
			scts := FormatSCTList(ext.Value)
			sb.WriteString(fmt.Sprintf("                %s\n", scts))

		// OCSP Must Staple
		case ext.Id.Equal(OidOCSPMustStaple):
			sb.WriteString("                OCSP Must-Staple\n")

		// CA/Browser Forum extensions
		case ext.Id.Equal(OidDomainValidated):
			sb.WriteString("                Domain Validated\n")
		case ext.Id.Equal(OidOrganizationValidate):
			sb.WriteString("                Organization Validated\n")
		case ext.Id.Equal(OidIndividualValidated):
			sb.WriteString("                Individual Validated\n")

		default:
			// Unknown extension - show raw data
			hexData := hex.EncodeToString(ext.Value)
			sb.WriteString(fmt.Sprintf("                %s\n", utils.FormatHexWithColons(hexData)))
		}
	}

	return sb.String()
}

// Individual extension formatting functions

func FormatSubjectKeyIdentifier(data []byte) string {
	var keyId []byte
	if _, err := asn1.Unmarshal(data, &keyId); err != nil {
		return hex.EncodeToString(data)
	}
	return utils.FormatHexWithColons(hex.EncodeToString(keyId))
}

func FormatAuthorityKeyIdentifier(data []byte) string {
	var aki struct {
		KeyIdentifier             []byte          `asn1:"optional,tag:0"`
		AuthorityCertIssuer       []asn1.RawValue `asn1:"optional,tag:1"`
		AuthorityCertSerialNumber *big.Int        `asn1:"optional,tag:2"`
	}

	if _, err := asn1.Unmarshal(data, &aki); err != nil {
		return hex.EncodeToString(data)
	}

	var result []string
	if len(aki.KeyIdentifier) > 0 {
		result = append(result, "keyid:"+utils.FormatHexWithColons(hex.EncodeToString(aki.KeyIdentifier)))
	}

	return strings.Join(result, "\n                ")
}

func FormatKeyUsage(keyUsage x509.KeyUsage) string {
	var usages []string
	if keyUsage&x509.KeyUsageDigitalSignature != 0 {
		usages = append(usages, "Digital Signature")
	}
	if keyUsage&x509.KeyUsageContentCommitment != 0 {
		usages = append(usages, "Non Repudiation")
	}
	if keyUsage&x509.KeyUsageKeyEncipherment != 0 {
		usages = append(usages, "Key Encipherment")
	}
	if keyUsage&x509.KeyUsageDataEncipherment != 0 {
		usages = append(usages, "Data Encipherment")
	}
	if keyUsage&x509.KeyUsageKeyAgreement != 0 {
		usages = append(usages, "Key Agreement")
	}
	if keyUsage&x509.KeyUsageCertSign != 0 {
		usages = append(usages, "Certificate Sign")
	}
	if keyUsage&x509.KeyUsageCRLSign != 0 {
		usages = append(usages, "CRL Sign")
	}
	if keyUsage&x509.KeyUsageEncipherOnly != 0 {
		usages = append(usages, "Encipher Only")
	}
	if keyUsage&x509.KeyUsageDecipherOnly != 0 {
		usages = append(usages, "Decipher Only")
	}
	return strings.Join(usages, ", ")
}

func FormatExtendedKeyUsage(extKeyUsage []x509.ExtKeyUsage) string {
	var usages []string
	for _, usage := range extKeyUsage {
		switch usage {
		case x509.ExtKeyUsageServerAuth:
			usages = append(usages, "TLS Web Server Authentication")
		case x509.ExtKeyUsageClientAuth:
			usages = append(usages, "TLS Web Client Authentication")
		case x509.ExtKeyUsageCodeSigning:
			usages = append(usages, "Code Signing")
		case x509.ExtKeyUsageEmailProtection:
			usages = append(usages, "E-mail Protection")
		case x509.ExtKeyUsageTimeStamping:
			usages = append(usages, "Time Stamping")
		case x509.ExtKeyUsageOCSPSigning:
			usages = append(usages, "OCSP Signing")
		}
	}
	return strings.Join(usages, ", ")
}

func FormatBasicConstraints(certificate *x509.Certificate) string {
	if !certificate.BasicConstraintsValid {
		return "CA:FALSE"
	}

	if certificate.IsCA {
		if certificate.MaxPathLen >= 0 {
			return fmt.Sprintf("CA:TRUE, pathlen:%d", certificate.MaxPathLen)
		}
		if certificate.MaxPathLenZero {
			return "CA:TRUE, pathlen:0"
		}
		return "CA:TRUE"
	}
	return "CA:FALSE"
}

func FormatSubjectAlternativeName(DNSNames []string, IPAddresses []net.IP, emailAddresses []string, URIs []*url.URL) string {
	var sans []string

	for _, dns := range DNSNames {
		sans = append(sans, fmt.Sprintf("DNS:%s", dns))
	}

	for _, ip := range IPAddresses {
		sans = append(sans, fmt.Sprintf("IP Address:%s", ip.String()))
	}

	for _, email := range emailAddresses {
		sans = append(sans, fmt.Sprintf("email:%s", email))
	}

	for _, uri := range URIs {
		sans = append(sans, fmt.Sprintf("URI:%s", uri.String()))
	}

	return strings.Join(sans, ", ")
}

func FormatIssuerAlternativeName(data []byte) string {
	// Parse IAN extension (similar structure to SAN)
	return "Issuer Alternative Name parsing not fully implemented"
}

func FormatCertificatePolicies(data []byte) string {
	var policies []struct {
		Policy     asn1.ObjectIdentifier
		Qualifiers []asn1.RawValue `asn1:"optional"`
	}

	if _, err := asn1.Unmarshal(data, &policies); err != nil {
		return hex.EncodeToString(data)
	}

	var result []string
	for _, policy := range policies {
		result = append(result, fmt.Sprintf("Policy: %s", policy.Policy.String()))
	}

	return strings.Join(result, "\n                ")
}

func FormatCRLDistributionPoints(data []byte) string {
	var cdp []struct {
		DistributionPoint struct {
			FullName []asn1.RawValue `asn1:"optional,tag:0"`
		} `asn1:"optional,tag:0"`
	}

	if _, err := asn1.Unmarshal(data, &cdp); err != nil {
		return hex.EncodeToString(data)
	}

	var result []string
	for _, dp := range cdp {
		for _, name := range dp.DistributionPoint.FullName {
			if name.Tag == 6 { // URI
				result = append(result, fmt.Sprintf("URI:%s", string(name.Bytes)))
			}
		}
	}

	return strings.Join(result, "\n                ")
}

func FormatAuthorityInfoAccess(data []byte) string {
	var aia []struct {
		Method   asn1.ObjectIdentifier
		Location asn1.RawValue
	}

	if _, err := asn1.Unmarshal(data, &aia); err != nil {
		return hex.EncodeToString(data)
	}

	var result []string
	for _, access := range aia {
		var method string
		switch {
		case access.Method.Equal([]int{1, 3, 6, 1, 5, 5, 7, 48, 1}):
			method = "OCSP"
		case access.Method.Equal([]int{1, 3, 6, 1, 5, 5, 7, 48, 2}):
			method = "CA Issuers"
		default:
			method = access.Method.String()
		}

		if access.Location.Tag == 6 { // URI
			result = append(result, fmt.Sprintf("%s - URI:%s", method, string(access.Location.Bytes)))
		}
	}

	return strings.Join(result, "\n                ")
}

func FormatInhibitAnyPolicy(data []byte) string {
	var skipCerts int
	if _, err := asn1.Unmarshal(data, &skipCerts); err != nil {
		return hex.EncodeToString(data)
	}
	return fmt.Sprintf("%d", skipCerts)
}

// FormatNameConstraints formats the NameConstraints from x509.Certificate
func FormatNameConstraints(cert *x509.Certificate) string {
	var result strings.Builder
	result.WriteString("Name Constraints:\n")

	// Permitted constraints
	if len(cert.PermittedDNSDomains) > 0 || len(cert.PermittedIPRanges) > 0 ||
		len(cert.PermittedEmailAddresses) > 0 || len(cert.PermittedURIDomains) > 0 {
		result.WriteString("    Permitted:\n")

		for _, domain := range cert.PermittedDNSDomains {
			result.WriteString(fmt.Sprintf("        DNS:%s\n", domain))
		}
		for _, email := range cert.PermittedEmailAddresses {
			result.WriteString(fmt.Sprintf("        email:%s\n", email))
		}
		for _, uri := range cert.PermittedURIDomains {
			result.WriteString(fmt.Sprintf("        URI:%s\n", uri))
		}
		for _, ipRange := range cert.PermittedIPRanges {
			result.WriteString(fmt.Sprintf("        IP Address:%s\n", ipRange.String()))
		}
	}

	// Excluded constraints
	if len(cert.ExcludedDNSDomains) > 0 || len(cert.ExcludedIPRanges) > 0 ||
		len(cert.ExcludedEmailAddresses) > 0 || len(cert.ExcludedURIDomains) > 0 {
		result.WriteString("    Excluded:\n")

		for _, domain := range cert.ExcludedDNSDomains {
			result.WriteString(fmt.Sprintf("        DNS:%s\n", domain))
		}
		for _, email := range cert.ExcludedEmailAddresses {
			result.WriteString(fmt.Sprintf("        email:%s\n", email))
		}
		for _, uri := range cert.ExcludedURIDomains {
			result.WriteString(fmt.Sprintf("        URI:%s\n", uri))
		}
		for _, ipRange := range cert.ExcludedIPRanges {
			result.WriteString(fmt.Sprintf("        IP Address:%s\n", ipRange.String()))
		}
	}

	return strings.TrimSuffix(result.String(), "\n")
}

// FormatPolicyConstraints formats Policy Constraints extension from raw ASN.1 data
func FormatPolicyConstraints(cert *x509.Certificate) string {
	var result strings.Builder
	result.WriteString("Policy Constraints:\n")

	if cert.RequireExplicitPolicy > 0 || cert.RequireExplicitPolicyZero {
		result.WriteString(fmt.Sprintf("    Require Explicit Policy: %d\n", cert.RequireExplicitPolicy))
	}

	if cert.InhibitPolicyMapping > 0 || cert.InhibitPolicyMappingZero {
		result.WriteString(fmt.Sprintf("    Inhibit Policy Mapping: %d\n", cert.InhibitPolicyMapping))
	}

	return strings.TrimSuffix(result.String(), "\n")
}

// FormatPolicyMappings formats the PolicyMappings from x509.Certificate
func FormatPolicyMappings(cert *x509.Certificate) string {
	var result strings.Builder
	result.WriteString("X509v3 Policy Mappings:\n")

	// Note: Go's x509 package doesn't directly expose policy mappings,
	// but we can work with PolicyIdentifiers
	for _, policy := range cert.PolicyMappings {
		result.WriteString(fmt.Sprintf("    %s:%s\n", policy.IssuerDomainPolicy.String(), policy.SubjectDomainPolicy.String()))
	}

	return strings.TrimSuffix(result.String(), "\n")
}

// FormatSCTList formats Certificate Transparency SCT List from raw data
func FormatSCTList(data []byte) string {
	if len(data) < 2 {
		return "Invalid SCT List: too short"
	}

	// First two bytes are the length of the SCT list
	listLen := int(data[0])<<8 | int(data[1])
	if len(data) < 2+listLen {
		return "Invalid SCT List: length mismatch"
	}

	var result strings.Builder
	result.WriteString("CT Precertificate SCTs:\n")

	offset := 2

	for offset < len(data) {
		if offset+2 > len(data) {
			break
		}

		// Each SCT is also length-prefixed
		sctLen := int(data[offset])<<8 | int(data[offset+1])
		offset += 2

		if offset+sctLen > len(data) {
			break
		}

		sctData := data[offset : offset+sctLen]
		result.WriteString("    Signed Certificate Timestamp:\n")
		result.WriteString(formatSCT(sctData))

		offset += sctLen
	}

	return strings.TrimSuffix(result.String(), "\n")
}

// Helper function to format individual SCT
func formatSCT(data []byte) string {
	if len(data) < 43 { // Minimum SCT size
		return "        Invalid SCT: too short\n"
	}

	var result strings.Builder

	// Version (1 byte)
	version := data[0]
	result.WriteString(fmt.Sprintf("        Version   : v1(%d)\n", version))

	// Log ID (32 bytes)
	logID := data[1:33]
	result.WriteString(fmt.Sprintf("        Log ID    : %s\n", strings.ToUpper(hex.EncodeToString(logID))))

	// Timestamp (8 bytes) - Convert to milliseconds since epoch
	timestamp := uint64(0)
	for i := 0; i < 8; i++ {
		timestamp = (timestamp << 8) | uint64(data[33+i])
	}
	result.WriteString(fmt.Sprintf("        Timestamp : %d\n", timestamp))

	// Extensions length (2 bytes)
	extLen := int(data[41])<<8 | int(data[42])
	if extLen > 0 {
		result.WriteString(fmt.Sprintf("        Extensions: %s\n", hex.EncodeToString(data[43:43+extLen])))
	} else {
		result.WriteString("        Extensions: none\n")
	}

	// Signature
	sigStart := 43 + extLen
	if sigStart+2 < len(data) {
		// Hash algorithm (1 byte) and signature algorithm (1 byte)
		hashAlg := data[sigStart]
		sigAlg := data[sigStart+1]
		result.WriteString(fmt.Sprintf("        Signature : %s-%s\n", getHashAlgorithm(hashAlg), getSignatureAlgorithm(sigAlg)))

		// Signature length (2 bytes)
		sigLen := int(data[sigStart+2])<<8 | int(data[sigStart+3])
		if sigStart+4+sigLen <= len(data) {
			signature := data[sigStart+4 : sigStart+4+sigLen]
			// Format signature in groups like OpenSSL
			sigHex := strings.ToUpper(hex.EncodeToString(signature))
			for i := 0; i < len(sigHex); i += 32 {
				end := i + 32
				if end > len(sigHex) {
					end = len(sigHex)
				}
				if i == 0 {
					result.WriteString(fmt.Sprintf("                    %s\n", sigHex[i:end]))
				} else {
					result.WriteString(fmt.Sprintf("                    %s\n", sigHex[i:end]))
				}
			}
		}
	}

	return result.String()
}

// Helper functions to convert algorithm IDs to names
func getHashAlgorithm(id byte) string {
	switch id {
	case 0:
		return "none"
	case 1:
		return "md5"
	case 2:
		return "sha1"
	case 3:
		return "sha224"
	case 4:
		return "sha256"
	case 5:
		return "sha384"
	case 6:
		return "sha512"
	default:
		return fmt.Sprintf("unknown(%d)", id)
	}
}

func getSignatureAlgorithm(id byte) string {
	switch id {
	case 0:
		return "anonymous"
	case 1:
		return "rsa"
	case 2:
		return "dsa"
	case 3:
		return "ecdsa"
	default:
		return fmt.Sprintf("unknown(%d)", id)
	}
}
