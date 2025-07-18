package cmd

var ReqHelpTemplate = `
NAME:
   cert-manager req - Create or view a Certificate Signing Request

USAGE:
   cert-manager req [options]

OPTIONS:
   --dns [ string ]                   DNS names to add to SANs list (REQUIRED)
   --commonName, --cn string          Subject Common Name
   --keyOpt string                    Specify key generation configuration: rsa:[bit-length], ec:[p256|p384|p521] (default: ec:p384)

   --hash, -s string                  Signature algorithim hash function: SHA256, SHA384, SHA512, PURE (default: "SHA256")
   --dsa, -d string                   Signature algorithim DSA: RSA, ECDSA, RSAPSS (default: "ECDSA")

   --country, -c string               Subject Country
   --org string, -o string            Subject Organization
   --orgUnit, --ou string             Choose signature algorithim
   --locality, -l string              Choose signature algorithim
   --state, --st string               Province or State
   --serialNumber string

   --email [ string ]                 Email addresses to add to SANs list
   --ip [ string ]                    IP addresses to add to SANs list

   --help, -h                         show help

`
var DecodeHelpTemplate = `
NAME:
   cert-manager decode - Decode and view a CSR or Certificate

USAGE:
   cert-manager decode [arguments...]

OPTIONS:
   --json      Output CSR in json format
   --help, -h  show help

`
