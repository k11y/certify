package csr

import (
	"cert-manager/certificates"
	"cert-manager/internal/utils"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/urfave/cli/v3"
)

type CSR struct {
	csr *x509.CertificateRequest
}

func ParseCSR(csrBytes []byte) (CSR, error) {
	csr, err := x509.ParseCertificateRequest(csrBytes)
	if err != nil {
		return CSR{}, err
	}

	return CSR{csr: csr}, nil

}

// Add more fields to this output
func (c CSR) PrintCSR() (string, error) {
	var sb strings.Builder

	sb.WriteString("Certificate Request:\n")
	sb.WriteString("    Data:\n")

	// Version
	// Fix version bracketing
	sb.WriteString("        Version: 1 (0x0)\n")
	// Subject
	sb.WriteString(fmt.Sprintf("        Subject: %s\n", c.csr.Subject.String()))
	// Public Key Info
	pkInfo, err := certificates.GetPublicKeyInfo(c.csr.PublicKeyAlgorithm.String(), c.csr.PublicKey)
	if err != nil {
		return "", err
	}
	sb.WriteString(pkInfo)
	// Extensions
	if len(c.csr.Extensions) > 0 {
		sb.WriteString("        Attributes:\n")
		sb.WriteString("                Requested Extensions:\n")
		sb.WriteString(c.formatExtensions())
	}

	// Signature Algorithm (repeated)
	sb.WriteString(fmt.Sprintf("    Signature Algorithm: %s\n", c.csr.SignatureAlgorithm.String()))

	// Signature
	signature := hex.EncodeToString(c.csr.Signature)
	sb.WriteString(utils.FormatHexBlock(signature, 8) + "\n")

	return sb.String(), nil

}

func (c CSR) formatExtensions() string {
	var sb strings.Builder

	// Process all extensions in order
	for _, ext := range c.csr.Extensions {
		extName, critical := certificates.GetExtensionName(ext.Id)

		if critical && ext.Critical {
			sb.WriteString(fmt.Sprintf("                    %s: critical\n", extName))
		} else {
			sb.WriteString(fmt.Sprintf("                    %s:\n", extName))
		}

		switch {
		// Subject Key Identifier
		case ext.Id.Equal(certificates.OidExtensionSubjectKeyId):
			ski := certificates.FormatSubjectKeyIdentifier(ext.Value)
			sb.WriteString(fmt.Sprintf("                        %s\n", ski))

		// Subject Alternative Name
		case ext.Id.Equal(certificates.OidExtensionSubjectAltName):
			san := certificates.FormatSubjectAlternativeName(c.csr.DNSNames, c.csr.IPAddresses, c.csr.EmailAddresses, c.csr.URIs)
			sb.WriteString(fmt.Sprintf("                        %s\n", san))

		// Certificate Policies
		case ext.Id.Equal(certificates.OidExtensionCertificatePolicies):
			policies := certificates.FormatCertificatePolicies(ext.Value)
			sb.WriteString(fmt.Sprintf("                        %s\n", policies))

		// Inhibit Any Policy
		case ext.Id.Equal(certificates.OidExtensionInhibitAnyPolicy):
			inhibit := certificates.FormatInhibitAnyPolicy(ext.Value)
			sb.WriteString(fmt.Sprintf("                        %s\n", inhibit))

		// CT Precertificate SCTs
		case ext.Id.Equal(certificates.OidExtensionPrecertificateSCT):
			scts := certificates.FormatSCTList(ext.Value)
			sb.WriteString(fmt.Sprintf("                        %s\n", scts))

		// OCSP Must Staple
		case ext.Id.Equal(certificates.OidOCSPMustStaple):
			sb.WriteString("                        OCSP Must-Staple\n")

		default:
			// Unknown extension - show raw data
			hexData := hex.EncodeToString(ext.Value)
			sb.WriteString(fmt.Sprintf("                        %s\n", utils.FormatHexWithColons(hexData)))
		}
	}

	return sb.String()
}

// Create Keys using other functions
// Confirmation if Common Name and SAN List are both empty
func CreateCSR(ctx context.Context, c *cli.Command) (err error) {
	signatureMap := map[string]map[string]x509.SignatureAlgorithm{
		"SHA256": {
			"RSA":    x509.SHA256WithRSA,
			"ECDSA":  x509.ECDSAWithSHA256,
			"RSAPSS": x509.SHA256WithRSAPSS,
		},
		"SHA384": {
			"RSA":    x509.SHA384WithRSA,
			"ECDSA":  x509.ECDSAWithSHA384,
			"RSAPSS": x509.SHA384WithRSAPSS,
		},
		"SHA512": {
			"RSA":    x509.SHA512WithRSA,
			"ECDSA":  x509.ECDSAWithSHA512,
			"RSAPSS": x509.SHA512WithRSAPSS,
		},
		"PURE": {
			"Ed25519": x509.PureEd25519,
		},
	}

	name := pkix.Name{
		Country:            []string{c.String("country")},
		Organization:       []string{c.String("organization")},
		OrganizationalUnit: []string{c.String("organizationalUnit")},
		Locality:           []string{c.String("locality")},
		Province:           []string{c.String("state")},
		SerialNumber:       c.String("serialNumber"),
		CommonName:         c.String("commonName"),
	}

	sig := strings.Split(strings.ToUpper(c.String("signature")), ":")
	dsa := sig[0]
	hash := sig[1]

	signatureAlg, ok := signatureMap[hash][dsa]
	if !ok {
		return fmt.Errorf("Invalid signature")
	}

	IPSlice := make([]net.IP, 0)

	for _, v := range c.StringSlice("ip") {
		IPSlice = append(IPSlice, net.ParseIP(v))

	}

	certRequest := x509.CertificateRequest{
		SignatureAlgorithm: signatureAlg,
		Subject:            name,
		DNSNames:           c.StringSlice("dns"),
		IPAddresses:        IPSlice,
		Version:            1,
	}

	// Generate key or read existing key

	// Switch to correct signature algorithim based on key alg
	keyConfig := strings.Split(c.String("keyOpt"), ":")
	keyAlg := strings.ToUpper(keyConfig[0])
	keyOpt := strings.ToUpper(keyConfig[1])
	var key any
	if keyAlg == "EC" {
		if dsa != "ECDSA" {
			return fmt.Errorf("Signature algorithim does not match key type")
		}

		var ec elliptic.Curve
		if keyOpt == "P256" {
			ec = elliptic.P256()
		} else if keyOpt == "P384" {
			ec = elliptic.P384()
		} else if keyOpt == "P521" {
			ec = elliptic.P521()
		} else {
			return fmt.Errorf("Invalid elliptic curve used in signature algorithim")
		}

		key, err = ecdsa.GenerateKey(ec, rand.Reader)
		if err != nil {
			return fmt.Errorf("Failed to generate key")
		}
	} else if keyAlg == "RSA" {
		if dsa != "RSA" && dsa != "RSAPSS" {
			return fmt.Errorf("Signature algorithim does not match key type")
		}

		bits, err := strconv.Atoi(keyOpt)
		if err != nil {
			return fmt.Errorf("Invalid bit configuration for RSA key")
		}
		key, err = rsa.GenerateKey(rand.Reader, bits)
		if err != nil {
			return fmt.Errorf("Failed to generate key")
		}
	} else {
		return fmt.Errorf("Invalid key generation algorithim")
	}

	csr, err := x509.CreateCertificateRequest(rand.Reader, &certRequest, key)
	if err != nil {
		return fmt.Errorf("Failed to create cert request")
	}

	// Create a PEM block
	pemBlock := &pem.Block{
		Type:  "CERTIFICATE REQUEST", // The type of the PEM block
		Bytes: csr,                   // The DER-encoded bytes
	}

	// Encode the PEM block to standard output
	if err := pem.Encode(os.Stdout, pemBlock); err != nil {
		log.Fatal(err)
	}

	return nil
}
