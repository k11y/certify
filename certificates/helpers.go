package certificates

import (
	"cert-manager/internal/utils"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"fmt"
)

// OID constants for extensions
var (
	OidExtensionSubjectKeyId          = []int{2, 5, 29, 14}
	OidExtensionKeyUsage              = []int{2, 5, 29, 15}
	OidExtensionExtendedKeyUsage      = []int{2, 5, 29, 37}
	OidExtensionAuthorityKeyId        = []int{2, 5, 29, 35}
	OidExtensionBasicConstraints      = []int{2, 5, 29, 19}
	OidExtensionSubjectAltName        = []int{2, 5, 29, 17}
	OidExtensionIssuerAltName         = []int{2, 5, 29, 18}
	OidExtensionCertificatePolicies   = []int{2, 5, 29, 32}
	OidExtensionNameConstraints       = []int{2, 5, 29, 30}
	OidExtensionCRLDistributionPoints = []int{2, 5, 29, 31}
	OidExtensionAuthorityInfoAccess   = []int{1, 3, 6, 1, 5, 5, 7, 1, 1}
	OidExtensionPolicyMappings        = []int{2, 5, 29, 33}
	OidExtensionPolicyConstraints     = []int{2, 5, 29, 36}
	OidExtensionInhibitAnyPolicy      = []int{2, 5, 29, 54}
	OidExtensionFreshestCRL           = []int{2, 5, 29, 46}
	OidExtensionPrecertificateSCT     = []int{1, 3, 6, 1, 4, 1, 11129, 2, 4, 2}
	OidExtensionEmailAddress          = []int{1, 2, 840, 113549, 1, 9, 1}
	OidTLSFeature                     = []int{1, 3, 6, 1, 5, 5, 7, 1, 24}
	OidDomainValidated                = []int{2, 23, 140, 1, 2, 2}
	OidOrganizationValidate           = []int{2, 23, 140, 1, 2, 1}
	OidIndividualValidated            = []int{2, 23, 140, 1, 2, 3}
	OidOCSPMustStaple                 = []int{1, 3, 6, 1, 5, 5, 7, 1, 24}
)

// Helper function to get extension name and criticality info
func GetExtensionName(oid asn1.ObjectIdentifier) (string, bool) {
	switch {
	case oid.Equal(OidExtensionSubjectKeyId):
		return "X509v3 Subject Key Identifier", false
	case oid.Equal(OidExtensionAuthorityKeyId):
		return "X509v3 Authority Key Identifier", false
	case oid.Equal(OidExtensionKeyUsage):
		return "X509v3 Key Usage", true
	case oid.Equal(OidExtensionExtendedKeyUsage):
		return "X509v3 Extended Key Usage", false
	case oid.Equal(OidExtensionBasicConstraints):
		return "X509v3 Basic Constraints", true
	case oid.Equal(OidExtensionSubjectAltName):
		return "X509v3 Subject Alternative Name", false
	case oid.Equal(OidExtensionIssuerAltName):
		return "X509v3 Issuer Alternative Name", false
	case oid.Equal(OidExtensionCertificatePolicies):
		return "X509v3 Certificate Policies", false
	case oid.Equal(OidExtensionCRLDistributionPoints):
		return "X509v3 CRL Distribution Points", false
	case oid.Equal(OidExtensionAuthorityInfoAccess):
		return "Authority Information Access", false
	case oid.Equal(OidExtensionNameConstraints):
		return "X509v3 Name Constraints", true
	case oid.Equal(OidExtensionPolicyConstraints):
		return "X509v3 Policy Constraints", true
	case oid.Equal(OidExtensionInhibitAnyPolicy):
		return "X509v3 Inhibit Any Policy", true
	case oid.Equal(OidExtensionPolicyMappings):
		return "X509v3 Policy Mappings", false
	case oid.Equal(OidExtensionFreshestCRL):
		return "X509v3 Freshest CRL", false
	case oid.Equal(OidExtensionPrecertificateSCT):
		return "CT Precertificate SCTs", false
	case oid.Equal(OidTLSFeature):
		return "TLS Feature", false
	case oid.Equal(OidDomainValidated):
		return "CA/B Forum Domain Validated", false
	case oid.Equal(OidOrganizationValidate):
		return "CA/B Forum Organization Validated", false
	case oid.Equal(OidIndividualValidated):
		return "CA/B Forum Individual Validated", false
	default:
		return "", false
	}
}

func BuildPublicKeyInfo(publicKeyAlgorithm x509.PublicKeyAlgorithm, publicKey any) PublicKeyInfo {
	pki := PublicKeyInfo{
		PublicKeyAlgorithm: publicKeyAlgorithm.String(),
	}

	switch pub := publicKey.(type) {
	case *rsa.PublicKey:
		pki.PublicKey = &PublicKey{
			KeySize:  fmt.Sprintf("%d", pub.N.BitLen()),
			Modulus:  utils.FormatHexWithColons(hex.EncodeToString(pub.N.Bytes())),
			Exponent: fmt.Sprintf("%d (0x%x)", pub.E, pub.E),
		}

	case *ecdsa.PublicKey:
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

		pki.PublicKey = &PublicKey{
			KeySize: fmt.Sprintf("%d", pub.Curve.Params().BitSize),
			Pub:     utils.FormatHexWithColons(hex.EncodeToString(pubKeyBytes)),
			ASN1OID: pub.Curve.Params().Name,
		}

		// Add NIST curve name if applicable
		switch pub.Curve.Params().Name {
		case "P-256":
			pki.PublicKey.NISTOID = "P-256"
		case "P-384":
			pki.PublicKey.NISTOID = "P-384"
		case "P-521":
			pki.PublicKey.NISTOID = "P-521"
		}

	case ed25519.PublicKey:
		pki.PublicKey = &PublicKey{
			Pub: utils.FormatHexWithColons(hex.EncodeToString(pub)),
		}
	}

	return pki
}

func BuildDistinguishedName(name pkix.Name) DistinguishedName {
	dn := DistinguishedName{
		Country:            name.Country,
		Organization:       name.Organization,
		OrganizationalUnit: name.OrganizationalUnit,
		Locality:           name.Locality,
		Province:           name.Province,
		StreetAddress:      name.StreetAddress,
		PostalCode:         name.PostalCode,
		SerialNumber:       name.SerialNumber,
		CommonName:         name.CommonName,
	}

	// Convert ExtraNames
	for _, n := range name.ExtraNames {
		if n.Type.Equal(OidExtensionEmailAddress) {
			if email, ok := n.Value.(string); ok {
				dn.EmailAddress = email
			}
		} else {
			dn.ExtraNames = append(dn.ExtraNames, Name{
				Type:  n.Type.String(),
				Value: fmt.Sprintf("%v", n.Value),
			})
		}
	}

	return dn
}
