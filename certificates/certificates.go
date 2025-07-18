package certificates

import (
	"cert-manager/csr"
	"crypto/x509"
	"time"
)

// Certificate struct
// Parse certificate
// Print cert - json and human readable

type Certificate struct {
	PublicKey           csr.PublicKey
	SignatureAlgorithim string

	Version      int
	SerialNumber string

	Subject             csr.Subject
	Issuer              csr.Subject
	NotBefore, NotAfter time.Time
	KeyUsage            string
	ExtKeyUsage         []string

	BasicConstraintsValid bool
	isCA                  bool

	MaxPathLen     int
	MaxPathLenZero bool

	SubjectKeyID   []byte
	AuthorityKeyID []byte

	OCSPServer            []string
	IssuingCertificateURL []string

	SAN csr.SAN

	NameConstraints NameConstraints

	CRLDistributionPoints []string

	// Does not translate a bunch of other extension and uncommon fields
	//PolicyIdentifiers (see note below)
	//Policies (see note below)
}

type NameConstraints struct {
	PermittedDNSDomainsCritical bool // if true then the name constraints are marked critical.
	PermittedDNSDomains         []string
	ExcludedDNSDomains          []string
	PermittedIPRanges           []string
	ExcludedIPRanges            []string
	PermittedEmailAddresses     []string
	ExcludedEmailAddresses      []string
	PermittedURIDomains         []string
	ExcludedURIDomains          []string
}

func ParseCertificate(certBytes []byte) {
	x509.Certificate

}
