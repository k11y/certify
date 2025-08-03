package certificates_test

import (
	"cert-manager/certificates"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Test configuration
type TestCertConfig struct {
	Name        string
	Template    x509.Certificate
	Extensions  []Extension
	Description string
}

type TestCSRConfig struct {
	Name        string
	Template    x509.CertificateRequest
	Extensions  []Extension
	Description string
}

type Extension struct {
	OID      asn1.ObjectIdentifier
	Critical bool
	Value    []byte
}

// Test helper to generate certificates with specific extensions
func generateCertWithExtensions(config TestCertConfig) ([]byte, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	// Create certificate
	certDER, err := x509.CreateCertificate(rand.Reader, &config.Template, &config.Template, &priv.PublicKey, priv)
	if err != nil {
		return nil, err
	}

	// Encode as PEM
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})
	return certPEM, nil
}

// Test helper to generate CSRs with specific extensions
func generateCSRWithExtensions(config TestCSRConfig) (*x509.CertificateRequest, []byte, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}

	// Add extensions to template
	for _, ext := range config.Extensions {
		config.Template.Extensions = append(config.Template.Extensions, pkix.Extension{
			Id:       ext.OID,
			Critical: ext.Critical,
			Value:    ext.Value,
		})
	}

	// Create CSR
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &config.Template, priv)
	if err != nil {
		return nil, nil, err
	}

	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		return nil, nil, err
	}

	// Encode as PEM
	csrPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrDER,
	})

	return csr, csrPEM, nil
}

// Get OpenSSL output for comparison
func getOpenSSLCertOutput(certPEM []byte) (string, error) {
	tmpFile, err := os.CreateTemp("", "test-cert-*.pem")
	if err != nil {
		return "", err
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.Write(certPEM); err != nil {
		return "", err
	}
	tmpFile.Close()

	cmd := exec.Command("openssl", "x509", "-in", tmpFile.Name(), "-text", "-noout")
	output, err := cmd.Output()
	if err != nil {
		return "", err
	}

	return string(output), nil
}

func getOpenSSLCSROutput(csrPEM []byte) (string, error) {
	tmpFile, err := os.CreateTemp("", "test-csr-*.pem")
	if err != nil {
		return "", err
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.Write(csrPEM); err != nil {
		return "", err
	}
	tmpFile.Close()

	cmd := exec.Command("openssl", "req", "-in", tmpFile.Name(), "-text", "-noout")
	output, err := cmd.Output()
	if err != nil {
		return "", err
	}

	return string(output), nil
}

// Certificate test configurations
func getCertificateTestConfigs() []TestCertConfig {
	now := time.Now()
	serialNumber := big.NewInt(1)

	return []TestCertConfig{
		{
			Name: "basic_ca_cert",
			Template: x509.Certificate{
				SerialNumber: serialNumber,
				Subject: pkix.Name{
					Organization:       []string{"Test CA"},
					Country:            []string{"US"},
					Province:           []string{"CA"},
					Locality:           []string{"San Francisco"},
					OrganizationalUnit: []string{"IT Department"},
					CommonName:         "Test CA Root",
				},
				NotBefore:             now,
				NotAfter:              now.Add(365 * 24 * time.Hour),
				KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
				ExtKeyUsage:           []x509.ExtKeyUsage{},
				BasicConstraintsValid: true,
				IsCA:                  true,
				MaxPathLen:            2,
			},
			Description: "Basic CA certificate with path length constraint",
		},
		{
			Name: "server_cert_with_san",
			Template: x509.Certificate{
				SerialNumber: big.NewInt(2),
				Subject: pkix.Name{
					Organization: []string{"Test Server"},
					Country:      []string{"US"},
					CommonName:   "test.example.com",
				},
				NotBefore:      now,
				NotAfter:       now.Add(90 * 24 * time.Hour),
				KeyUsage:       x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
				ExtKeyUsage:    []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
				DNSNames:       []string{"test.example.com", "www.test.example.com", "api.test.example.com"},
				IPAddresses:    []net.IP{net.ParseIP("192.168.1.100"), net.ParseIP("10.0.0.1")},
				EmailAddresses: []string{"admin@test.example.com"},
			},
			Description: "Server certificate with multiple SAN entries",
		},
		{
			Name: "client_cert",
			Template: x509.Certificate{
				SerialNumber: big.NewInt(3),
				Subject: pkix.Name{
					Organization: []string{"Test Client"},
					Country:      []string{"GB"},
					CommonName:   "client@example.com",
				},
				NotBefore:      now,
				NotAfter:       now.Add(30 * 24 * time.Hour),
				KeyUsage:       x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
				ExtKeyUsage:    []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageEmailProtection},
				EmailAddresses: []string{"client@example.com", "backup@example.com"},
			},
			Description: "Client certificate for authentication and email protection",
		},
		{
			Name: "code_signing_cert",
			Template: x509.Certificate{
				SerialNumber: big.NewInt(4),
				Subject: pkix.Name{
					Organization: []string{"Software Vendor"},
					Country:      []string{"DE"},
					CommonName:   "Code Signer",
				},
				NotBefore:   now,
				NotAfter:    now.Add(730 * 24 * time.Hour),
				KeyUsage:    x509.KeyUsageDigitalSignature,
				ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
			},
			Description: "Code signing certificate",
		},
		{
			Name: "ocsp_signing_cert",
			Template: x509.Certificate{
				SerialNumber: big.NewInt(5),
				Subject: pkix.Name{
					Organization: []string{"OCSP Responder"},
					Country:      []string{"FR"},
					CommonName:   "OCSP Signer",
				},
				NotBefore:   now,
				NotAfter:    now.Add(365 * 24 * time.Hour),
				KeyUsage:    x509.KeyUsageDigitalSignature,
				ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageOCSPSigning},
			},
			Description: "OCSP signing certificate",
		},
		{
			Name: "intermediate_ca",
			Template: x509.Certificate{
				SerialNumber: big.NewInt(6),
				Subject: pkix.Name{
					Organization: []string{"Intermediate CA"},
					Country:      []string{"JP"},
					CommonName:   "Test Intermediate CA",
				},
				NotBefore:             now,
				NotAfter:              now.Add(1825 * 24 * time.Hour), // 5 years
				KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
				BasicConstraintsValid: true,
				IsCA:                  true,
				MaxPathLen:            0, // Can't sign other CAs
			},
			Description: "Intermediate CA with path length 0",
		},
	}
}

// CSR test configurations
func getCSRTestConfigs() []TestCSRConfig {
	sanExtension, _ := marshalSAN([]string{"test.example.com", "www.example.com"}, []net.IP{net.ParseIP("192.168.1.1")}, []string{"test@example.com"})
	keyUsageExt, _ := marshalKeyUsage(x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment)
	extKeyUsageExt, _ := marshalExtKeyUsage([]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})

	return []TestCSRConfig{
		{
			Name: "basic_server_csr",
			Template: x509.CertificateRequest{
				Subject: pkix.Name{
					Organization: []string{"Test Server CSR"},
					Country:      []string{"US"},
					CommonName:   "server.example.com",
				},
				DNSNames:    []string{"server.example.com", "www.server.example.com"},
				IPAddresses: []net.IP{net.ParseIP("10.0.0.10")},
			},
			Extensions: []Extension{
				{
					OID:      asn1.ObjectIdentifier{2, 5, 29, 17}, // SAN
					Critical: false,
					Value:    sanExtension,
				},
				{
					OID:      asn1.ObjectIdentifier{2, 5, 29, 15}, // Key Usage
					Critical: true,
					Value:    keyUsageExt,
				},
				{
					OID:      asn1.ObjectIdentifier{2, 5, 29, 37}, // Extended Key Usage
					Critical: false,
					Value:    extKeyUsageExt,
				},
			},
			Description: "Server CSR with SAN, Key Usage, and Extended Key Usage",
		},
		{
			Name: "client_csr",
			Template: x509.CertificateRequest{
				Subject: pkix.Name{
					Organization: []string{"Client Org"},
					Country:      []string{"GB"},
					CommonName:   "client.example.com",
				},
				EmailAddresses: []string{"client@example.com"},
			},
			Description: "Client CSR for authentication",
		},
		{
			Name: "wildcard_csr",
			Template: x509.CertificateRequest{
				Subject: pkix.Name{
					Organization: []string{"Wildcard Cert"},
					Country:      []string{"CA"},
					CommonName:   "*.example.com",
				},
				DNSNames: []string{"*.example.com", "example.com"},
			},
			Description: "Wildcard certificate request",
		},
	}
}

// Helper functions for marshaling extensions
func marshalSAN(dnsNames []string, ipAddresses []net.IP, emailAddresses []string) ([]byte, error) {
	var rawValues []asn1.RawValue

	for _, name := range dnsNames {
		rawValues = append(rawValues, asn1.RawValue{Tag: 2, Class: 2, Bytes: []byte(name)})
	}

	for _, ip := range ipAddresses {
		rawValues = append(rawValues, asn1.RawValue{Tag: 7, Class: 2, Bytes: ip})
	}

	for _, email := range emailAddresses {
		rawValues = append(rawValues, asn1.RawValue{Tag: 1, Class: 2, Bytes: []byte(email)})
	}

	return asn1.Marshal(rawValues)
}

func marshalKeyUsage(usage x509.KeyUsage) ([]byte, error) {
	var a [2]byte
	a[0] = byte(usage)
	a[1] = byte(usage >> 8)

	l := 1
	if a[1] != 0 {
		l = 2
	}

	bitString := asn1.BitString{Bytes: a[:l], BitLength: l * 8}
	return asn1.Marshal(bitString)
}

func marshalExtKeyUsage(usage []x509.ExtKeyUsage) ([]byte, error) {
	var oids []asn1.ObjectIdentifier
	for _, u := range usage {
		switch u {
		case x509.ExtKeyUsageServerAuth:
			oids = append(oids, asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 1})
		case x509.ExtKeyUsageClientAuth:
			oids = append(oids, asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 2})
		case x509.ExtKeyUsageCodeSigning:
			oids = append(oids, asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 3})
		case x509.ExtKeyUsageEmailProtection:
			oids = append(oids, asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 4})
		}
	}
	return asn1.Marshal(oids)
}

// Main test functions
func TestCertificateFormatting(t *testing.T) {
	// Replace with your actual formatter
	configs := getCertificateTestConfigs()

	for _, config := range configs {
		t.Run(config.Name, func(t *testing.T) {
			// Generate certificate
			certPEM, err := generateCertWithExtensions(config)
			if err != nil {
				t.Fatalf("Failed to generate certificate: %v", err)
			}

			// Get OpenSSL output
			opensslOutput, err := getOpenSSLCertOutput(certPEM)
			if err != nil {
				t.Fatalf("Failed to get OpenSSL output: %v", err)
			}

			// Get formatter output

			p, _ := pem.Decode(certPEM)
			cert, err := certificates.ParseCertificate(p.Bytes)
			if err != nil {
				t.Fatalf("Formatter failed: %v", err)
			}
			formatterOutput, err := cert.PrintCertificate()

			// Save outputs for manual inspection
			saveTestOutput(t, config.Name, "openssl", opensslOutput)
			saveTestOutput(t, config.Name, "formatter", formatterOutput)

			// Compare key sections
			validateCertificateOutput(t, config.Name, opensslOutput, formatterOutput)
		})
	}
}

//func TestCSRFormatting(t *testing.T) {
//	// Replace with your actual formatter
//
//	configs := getCSRTestConfigs()
//
//	for _, config := range configs {
//		t.Run(config.Name, func(t *testing.T) {
//			// Generate CSR
//			csr, csrPEM, err := generateCSRWithExtensions(config)
//			if err != nil {
//				t.Fatalf("Failed to generate CSR: %v", err)
//			}
//
//			// Get OpenSSL output
//			opensslOutput, err := getOpenSSLCSROutput(csrPEM)
//			if err != nil {
//				t.Fatalf("Failed to get OpenSSL output: %v", err)
//			}
//
//			// Get formatter output
//			formatterOutput, err :=
//			if err != nil {
//				t.Fatalf("Formatter failed: %v", err)
//			}
//
//			// Save outputs for manual inspection
//			saveTestOutput(t, config.Name, "openssl-csr", opensslOutput)
//			saveTestOutput(t, config.Name, "formatter-csr", formatterOutput)
//
//			// Compare key sections
//			validateCSROutput(t, config.Name, opensslOutput, formatterOutput)
//		})
//	}
//}

func saveTestOutput(t *testing.T, testName, outputType, content string) {
	dir := filepath.Join("test_outputs", testName)
	os.MkdirAll(dir, 0755)

	filename := filepath.Join(dir, outputType+".txt")
	err := os.WriteFile(filename, []byte(content), 0644)
	if err != nil {
		t.Logf("Warning: Could not save %s output: %v", outputType, err)
	}
}

func validateCertificateOutput(t *testing.T, testName, opensslOutput, formatterOutput string) {
	// Extract and compare key sections
	sections := []string{
		"Version:",
		"Serial Number:",
		"Signature Algorithm:",
		"Issuer:",
		"Validity",
		"Subject:",
		"X509v3 Basic Constraints:",
		"X509v3 Key Usage:",
		"X509v3 Extended Key Usage:",
		"X509v3 Subject Alternative Name:",
		"X509v3 Authority Key Identifier:",
		"X509v3 Subject Key Identifier:",
	}

	for _, section := range sections {
		opensslSection := extractSection(opensslOutput, section)
		formatterSection := extractSection(formatterOutput, section)

		if opensslSection != "" && formatterSection == "" {
			t.Errorf("Test %s: Missing section '%s' in formatter output", testName, section)
		}

		// Additional specific validations can be added here
		if section == "Version:" {
			if !strings.Contains(formatterSection, "3 (0x2)") && strings.Contains(opensslSection, "3 (0x2)") {
				t.Errorf("Test %s: Version format mismatch", testName)
			}
		}
	}
}

func validateCSROutput(t *testing.T, testName, opensslOutput, formatterOutput string) {
	// Extract and compare key sections for CSRs
	sections := []string{
		"Version:",
		"Subject:",
		"Subject Public Key Info:",
		"Public Key Algorithm:",
		"Requested Extensions:",
	}

	for _, section := range sections {
		opensslSection := extractSection(opensslOutput, section)
		formatterSection := extractSection(formatterOutput, section)

		if opensslSection != "" && formatterSection == "" {
			t.Errorf("Test %s: Missing section '%s' in formatter output", testName, section)
		}
	}
}

func extractSection(output, sectionName string) string {
	lines := strings.Split(output, "\n")
	var sectionLines []string
	inSection := false

	for _, line := range lines {
		if strings.Contains(line, sectionName) {
			inSection = true
			sectionLines = append(sectionLines, line)
			continue
		}

		if inSection {
			if strings.HasPrefix(line, "        ") || strings.HasPrefix(line, "            ") {
				sectionLines = append(sectionLines, line)
			} else if strings.TrimSpace(line) != "" && !strings.HasPrefix(line, "    ") {
				break
			}
		}
	}

	return strings.Join(sectionLines, "\n")
}

// Benchmark tests
//func BenchmarkCertificateFormatting(b *testing.B) {
//	var formatterX509Formatter // = YourFormatterImplementation{}
//
//	config := getCertificateTestConfigs()[0] // Use basic CA cert
//	cert, _, err := generateCertWithExtensions(config)
//	if err != nil {
//		b.Fatalf("Failed to generate certificate: %v", err)
//	}
//
//	b.ResetTimer()
//	for i := 0; i < b.N; i++ {
//		_, err := formatter.FormatCertificateAsOpenSSL(cert)
//		if err != nil {
//			b.Fatalf("Formatting failed: %v", err)
//		}
//	}
//}
//
//func BenchmarkCSRFormatting(b *testing.B) {
//	var formatter X509Formatter // = YourFormatterImplementation{}
//
//	config := getCSRTestConfigs()[0] // Use basic server CSR
//	csr, _, err := generateCSRWithExtensions(config)
//	if err != nil {
//		b.Fatalf("Failed to generate CSR: %v", err)
//	}
//
//	b.ResetTimer()
//	for i := 0; i < b.N; i++ {
//		_, err := formatter.FormatCSRAsOpenSSL(csr)
//		if err != nil {
//			b.Fatalf("Formatting failed: %v", err)
//		}
//	}
//}
