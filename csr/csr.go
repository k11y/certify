package csr

import (
	"cert-manager/internal/utils"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"

	"github.com/urfave/cli/v3"
)

type CSRMapping struct {
	raw                *x509.CertificateRequest
	PublicKey          PublicKey `json:"publicKey"`
	SignatureAlgorithm string    `json:"signatureAlgorithim"`
	Subject            Subject   `json:"subject"`
	SAN                SAN       `json:"san"`
}

type PublicKey struct {
	Modulus  string `json:"modulus,omitempty"`
	Exponent int    `json:"exponent,omitempty"`
	Pub      string `json:"pub,omitempty"`
}

type Subject struct {
	CommonName         string `json:"commonName"`
	Country            string `json:"country"`
	Organization       string `json:"organization"`
	OrganizationalUnit string `json:"organizationalUnit"`
	Locality           string `json:"locality"`
	State              string `json:"state"`
	SerialNumber       string `json:"serialNumber"`
}

type SAN struct {
	DNS    []string `json:"dns"`
	IP     []string `json:"ip"`
	Emails []string `json:"email"`
	URIs   []string
}

func ParseCSR(csrBytes []byte) (CSRMapping, error) {
	csr, err := x509.ParseCertificateRequest(csrBytes)
	if err != nil {
		return CSRMapping{}, err
	}

	var pk PublicKey
	if csr.SignatureAlgorithm == x509.SHA512WithRSA || csr.SignatureAlgorithm == x509.SHA384WithRSA || csr.SignatureAlgorithm == x509.SHA256WithRSA {

		rsaKey, ok := csr.PublicKey.(*rsa.PublicKey)
		if !ok {
			return CSRMapping{}, fmt.Errorf("Failed to read public key")
		}
		pk.Modulus = fmt.Sprintf("%x", rsaKey.N.Bytes())
		pk.Exponent = rsaKey.E

	} else if csr.SignatureAlgorithm == x509.ECDSAWithSHA512 || csr.SignatureAlgorithm == x509.ECDSAWithSHA384 || csr.SignatureAlgorithm == x509.ECDSAWithSHA256 {
		ecKey, err := csr.PublicKey.(*ecdsa.PublicKey).ECDH()
		if err != nil {
			return CSRMapping{}, err
		}
		pk.Pub = fmt.Sprintf("%x", ecKey.Bytes())

	}

	mapping := CSRMapping{
		raw: csr,
		// Key type which allows to print both rsa and ecc type keys
		PublicKey:          pk,
		SignatureAlgorithm: csr.SignatureAlgorithm.String(),
		Subject: Subject{
			CommonName:         csr.Subject.CommonName,
			Country:            utils.GetFirstIndex(csr.Subject.Country),
			Organization:       utils.GetFirstIndex(csr.Subject.Organization),
			OrganizationalUnit: utils.GetFirstIndex(csr.Subject.OrganizationalUnit),
			Locality:           utils.GetFirstIndex(csr.Subject.Locality),
			State:              utils.GetFirstIndex(csr.Subject.Province),
			SerialNumber:       csr.Subject.SerialNumber,
		},
		SAN: SAN{
			DNS: csr.DNSNames,
		},
	}

	return mapping, nil
}

// Add more fields to this output
func (c CSRMapping) PrintCSR() (string, error) {
	template := `
Public Key: 
  %s

Signature Algorithim: %s

Subject:
  Common Name: %s
  Country: %s
  Organization: %s
  Organizational Unit: %s
  Locality: %s
  State: %s
  Serial Number: %s

SANs:
  DNS: %v`

	keyTemplate := `
  Modulus:
    %s

  Exponent:
    %d`

	var key string
	if c.PublicKey.Pub != "" {
		key = utils.WrapText(c.PublicKey.Pub, 30, "\n  ")
	} else if c.PublicKey.Modulus != "" {

		key = fmt.Sprintf(keyTemplate, utils.WrapText(c.PublicKey.Modulus, 75, "\n    "), c.PublicKey.Exponent)
	}

	csrStr := fmt.Sprintf(template+"\n\n",
		key,
		c.SignatureAlgorithm,
		c.Subject.CommonName,
		c.Subject.Country,
		c.Subject.Organization,
		c.Subject.OrganizationalUnit,
		c.Subject.Locality,
		c.Subject.State,
		c.Subject.SerialNumber,
		c.SAN.DNS)

	return csrStr, nil
}

func (c CSRMapping) JsonCSR() (string, error) {

	out, err := json.MarshalIndent(c, "", "    ")
	if err != nil {
		return "", err
	}

	return string(out), nil
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
	certRequest := x509.CertificateRequest{
		SignatureAlgorithm: signatureAlg,
		Subject:            name,
		DNSNames:           c.StringSlice("dns"),
	}

	// Generate key or read existing key

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
