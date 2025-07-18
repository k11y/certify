package main

import (
	"bufio"
	"cert-manager/cmd"
	"cert-manager/csr"
	"cert-manager/internal/utils"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"os"

	"github.com/urfave/cli/v3"
)

type CLI struct {
	scanner *bufio.Scanner
}

func main() {

	//scanner := bufio.NewScanner(os.Stdin)

	//var config tls.Config
	//conn, err := tls.Dial("tcp", "google.com:443", &config)
	//if err != nil {
	//	fmt.Println(err)
	//	os.Exit(1)
	//}

	setupCLI()

}

func setupCLI() {
	// Check to make sure CN is included in SAN List
	// If no flags are used, go through interactive prompt - or use -i flag for interactive?
	// Should any field be mandatory?
	cli.SubcommandHelpTemplate = cmd.ReqHelpTemplate
	req := cli.Command{
		Name:  "req",
		Usage: "Create or view a Certificate Signing Request",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:    "commonName",
				Aliases: []string{"cn"},
				Value:   "",
				Usage:   "",
			},
			&cli.StringSliceFlag{
				Name:  "dns",
				Usage: "DNS names valid for this cert",
			},
			&cli.StringFlag{
				Name:  "keyOpt",
				Value: "EC:P384",
				Usage: "Specify key generation configuration: RSA:[bit-length], EC:[P256|P384|P521]",
			},
			&cli.StringFlag{
				Name:    "country",
				Aliases: []string{"c"},
				Value:   "",
				Usage:   "Country of cert",
			},
			&cli.StringFlag{
				Name:    "org",
				Aliases: []string{"o"},
				Value:   "",
				Usage:   "Organization of cert",
			},
			&cli.StringFlag{
				Name:    "signature",
				Aliases: []string{"s"},
				Value:   "ECDSA:SHA256",
				Usage:   "Choose signature algorithim: [RSA, ECDSA, RSAPSS]:[SHA256, SHA384, SHA512]",
			},
			&cli.StringFlag{
				Name:    "orgUnit",
				Aliases: []string{"ou"},
				Value:   "",
				Usage:   "Choose signature algorithim",
			},
			&cli.StringFlag{
				Name:    "locality",
				Aliases: []string{"l"},
				Value:   "",
				Usage:   "Choose signature algorithim",
			},
			&cli.StringFlag{
				Name:    "state",
				Aliases: []string{"st"},
				Value:   "",
				Usage:   "Province or State",
			},
			&cli.StringFlag{
				Name:  "serialNumber",
				Value: "",
				Usage: "",
			},
			&cli.StringSliceFlag{
				Name:  "email",
				Usage: "Email addresses valid for this cert",
			},
			&cli.StringSliceFlag{
				Name:  "ip",
				Usage: "IP addresses valid for this cert",
			},
		},
		CustomHelpTemplate: cmd.ReqHelpTemplate,
		Action:             csr.CreateCSR,
	}

	decode := cli.Command{
		Name:  "decode",
		Usage: "Decode and view a CSR or Certificate",
		Flags: []cli.Flag{
			&cli.BoolFlag{
				Name:  "json",
				Usage: "Output CSR in json format",
			},
		},
		Arguments: []cli.Argument{
			&cli.StringArg{
				Name:      "decodeTarget",
				UsageText: "[filePath]",
			},
		},
		Action: decodeCertCmd,
	}

	cmd := &cli.Command{
		Commands: []*cli.Command{
			&req,
			&decode,
		},
	}

	if err := cmd.Run(context.Background(), os.Args); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func getCert(domain string, port int) {
	//var config tls.Config
	//addr := fmt.Sprintf("%s:%d", domain, port)
	//conn, err := tls.Dial("tcp", addr, &config)
	//if err != nil {
	//	fmt.Println(err)
	//	os.Exit(1)
	//}

	//conn.ConnectionState().PeerCertificates

}

func decodeCertCmd(ctx context.Context, c *cli.Command) (err error) {
	var data []byte
	decodeTarget := c.StringArg("decodeTarget")
	if decodeTarget == "" && utils.IsInputPiped() {
		data, err = io.ReadAll(os.Stdin)
		if err != nil {
			return cli.Exit("Failed to read piped value", 1)
		}

	} else if decodeTarget == "" {
		cli.SubcommandHelpTemplate = cmd.DecodeHelpTemplate
		cli.ShowSubcommandHelp(c)
		return cli.Exit("Missing decode target", 2)
	} else {
		f, err := os.Open(decodeTarget)
		if err != nil {
			return cli.Exit("Failed to read open file", 1)
		}

		data, err = io.ReadAll(f)
		if err != nil {
			return cli.Exit("Failed to read file", 1)
		}
	}

	certOut, err := decodeCert(data, c.Bool("json"))
	if err != nil {
		return cli.Exit("Failed to decode", 1)
	}

	fmt.Println(certOut)

	return nil
}

func decodeCert(data []byte, json bool) (string, error) {
	p, _ := pem.Decode(data)

	if p.Type == "CERTIFICATE REQUEST" {
		csr, err := csr.ParseCSR(p.Bytes)
		if err != nil {
			return "", err
		}

		if json {
			return csr.JsonCSR()
		} else {
			return csr.PrintCSR()
		}

	} else if p.Type == "CERTIFICATE" {
		req, err := x509.ParseCertificate(p.Bytes)
		if err != nil {
			return "", err
		}

		fmt.Println(req)
	}

	return "", fmt.Errorf("invalid certificate headers")
}

// View certificates from existing sites
// View certificates on local machine
// Create/View CSRs
// Create self-signed certificate
// Sign CSR
