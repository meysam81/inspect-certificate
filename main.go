package main

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"flag"
	"fmt"
	"math/big"
	"net"
	"os"
	"slices"
	"strings"
	"time"
)

var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
	builtBy = "unknown"

	validFormats = []string{"openssl", "minimal"}
)

func main() {
	var format string
	flag.StringVar(&format, "format", "minimal", "Output format: minimal or openssl")

	var ver bool
	flag.BoolVar(&ver, "v", false, "print version")
	flag.BoolVar(&ver, "version", false, "print version")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [--format=minimal|openssl] <domain>\n", os.Args[0])
		flag.PrintDefaults()
	}
	flag.Parse()

	if ver {
		fmt.Printf("Version:    %s\n", version)
		fmt.Printf("Commit:     %s\n", commit)
		fmt.Printf("Build Date: %s\n", date)
		fmt.Printf("Built By:   %s\n", builtBy)
		return
	}

	if flag.NArg() < 1 {
		flag.Usage()
		os.Exit(1)
	}

	if !slices.Contains(validFormats, format) {
		fmt.Fprintf(os.Stderr, "Unknown format: %s, valid formats: %v\n", format, strings.Join(validFormats, ", "))
		os.Exit(1)
	}

	domain := flag.Arg(0)
	domain = strings.TrimPrefix(domain, "https://")
	domain = strings.TrimPrefix(domain, "http://")
	domain = strings.Split(domain, "/")[0]

	host := domain
	if !strings.Contains(domain, ":") {
		host = domain + ":443"
	}

	conn, err := tls.DialWithDialer(
		&net.Dialer{Timeout: 10 * time.Second},
		"tcp",
		host,
		&tls.Config{InsecureSkipVerify: true},
	)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error connecting to %s: %v\n", host, err)
		os.Exit(1)
	}
	defer func() { _ = conn.Close() }()

	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		fmt.Fprintln(os.Stderr, "No certificates found")
		os.Exit(1)
	}

	cert := certs[0]

	switch format {
	case "openssl":
		printOpenSSL(cert)
	case "minimal":
		printMinimal(cert)
	}
}

func printMinimal(cert *x509.Certificate) {
	fmt.Printf("Subject:     %s\n", cert.Subject.CommonName)
	fmt.Printf("Issuer:      %s\n", formatIssuer(cert))
	fmt.Printf("Valid From:  %s\n", cert.NotBefore.UTC().Format("Jan 02 2006 15:04:05 UTC"))
	fmt.Printf("Valid Until: %s\n", cert.NotAfter.UTC().Format("Jan 02 2006 15:04:05 UTC"))

	days := int(time.Until(cert.NotAfter).Hours() / 24)
	if days < 0 {
		fmt.Printf("Status:      EXPIRED (%d days ago)\n", -days)
	} else if days < 30 {
		fmt.Printf("Status:      EXPIRING SOON (%d days left)\n", days)
	} else {
		fmt.Printf("Status:      Valid (%d days left)\n", days)
	}

	if len(cert.DNSNames) > 0 {
		fmt.Printf("DNS Names:   %s\n", strings.Join(cert.DNSNames, ", "))
	}

	fmt.Printf("Serial:      %s\n", formatSerial(cert.SerialNumber))
}

func printOpenSSL(cert *x509.Certificate) {
	fmt.Println("Certificate:")
	fmt.Println("    Data:")
	fmt.Printf("        Version: %d (0x%x)\n", cert.Version, cert.Version-1)
	fmt.Printf("        Serial Number: %s (0x%x)\n", cert.SerialNumber.String(), cert.SerialNumber)
	fmt.Printf("    Signature Algorithm: %s\n", cert.SignatureAlgorithm)
	fmt.Printf("        Issuer: %s\n", formatIssuer(cert))
	fmt.Println("        Validity")
	fmt.Printf("            Not Before: %s\n", cert.NotBefore.UTC().Format("Jan 02 15:04:05 2006 UTC"))
	fmt.Printf("            Not After : %s\n", cert.NotAfter.UTC().Format("Jan 02 15:04:05 2006 UTC"))
	fmt.Printf("        Subject: CN=%s\n", cert.Subject.CommonName)
	fmt.Println("        Subject Public Key Info:")
	printPublicKeyInfo(cert)
	printExtensions(cert)
	fmt.Printf("    Signature Algorithm: %s\n", cert.SignatureAlgorithm)
	printSignature(cert.Signature)
}

func formatIssuer(cert *x509.Certificate) string {
	var parts []string
	if len(cert.Issuer.Country) > 0 {
		parts = append(parts, "C="+cert.Issuer.Country[0])
	}
	if len(cert.Issuer.Organization) > 0 {
		parts = append(parts, "O="+cert.Issuer.Organization[0])
	}
	if cert.Issuer.CommonName != "" {
		parts = append(parts, "CN="+cert.Issuer.CommonName)
	}
	return strings.Join(parts, ", ")
}

func formatSerial(n *big.Int) string {
	b := n.Bytes()
	var parts []string
	for _, v := range b {
		parts = append(parts, fmt.Sprintf("%02x", v))
	}
	return strings.Join(parts, ":")
}

func printPublicKeyInfo(cert *x509.Certificate) {
	switch pub := cert.PublicKey.(type) {
	case *ecdsa.PublicKey:
		fmt.Printf("            Public Key Algorithm: ECDSA\n")
		fmt.Printf("                Public-Key: (%d bit)\n", pub.Curve.Params().BitSize)
		fmt.Println("                X:")
		printHexBlock(pub.X.Bytes(), 20)
		fmt.Println("                Y:")
		printHexBlock(pub.Y.Bytes(), 20)
		fmt.Printf("                Curve: %s\n", pub.Curve.Params().Name)
	case *rsa.PublicKey:
		fmt.Printf("            Public Key Algorithm: RSA\n")
		fmt.Printf("                Public-Key: (%d bit)\n", pub.N.BitLen())
		fmt.Println("                Modulus:")
		printHexBlock(pub.N.Bytes(), 20)
		fmt.Printf("                Exponent: %d (0x%x)\n", pub.E, pub.E)
	default:
		fmt.Printf("            Public Key Algorithm: Unknown\n")
	}
}

func printHexBlock(data []byte, indent int) {
	hexStr := hex.EncodeToString(data)
	prefix := strings.Repeat(" ", indent)
	for i := 0; i < len(hexStr); i += 30 {
		end := i + 30
		if end > len(hexStr) {
			end = len(hexStr)
		}
		line := hexStr[i:end]
		var formatted []string
		for j := 0; j < len(line); j += 2 {
			formatted = append(formatted, line[j:j+2])
		}
		fmt.Printf("%s%s\n", prefix, strings.Join(formatted, ":"))
	}
}

func printExtensions(cert *x509.Certificate) {
	fmt.Println("        X509v3 extensions:")

	if cert.KeyUsage != 0 {
		fmt.Println("            X509v3 Key Usage: critical")
		fmt.Printf("                %s\n", formatKeyUsage(cert.KeyUsage))
	}

	if len(cert.ExtKeyUsage) > 0 {
		fmt.Println("            X509v3 Extended Key Usage:")
		fmt.Printf("                %s\n", formatExtKeyUsage(cert.ExtKeyUsage))
	}

	fmt.Println("            X509v3 Basic Constraints: critical")
	fmt.Printf("                CA:%v\n", strings.ToUpper(fmt.Sprintf("%v", cert.IsCA)))

	if len(cert.SubjectKeyId) > 0 {
		fmt.Println("            X509v3 Subject Key Identifier:")
		fmt.Printf("                %s\n", formatKeyID(cert.SubjectKeyId))
	}

	if len(cert.AuthorityKeyId) > 0 {
		fmt.Println("            X509v3 Authority Key Identifier:")
		fmt.Printf("                keyid:%s\n", formatKeyID(cert.AuthorityKeyId))
	}

	if len(cert.OCSPServer) > 0 || len(cert.IssuingCertificateURL) > 0 {
		fmt.Println("            Authority Information Access:")
		for _, ocsp := range cert.OCSPServer {
			fmt.Printf("                OCSP - URI:%s\n", ocsp)
		}
		for _, ca := range cert.IssuingCertificateURL {
			fmt.Printf("                CA Issuers - URI:%s\n", ca)
		}
	}

	if len(cert.DNSNames) > 0 {
		fmt.Println("            X509v3 Subject Alternative Name:")
		var sans []string
		for _, dns := range cert.DNSNames {
			sans = append(sans, "DNS:"+dns)
		}
		fmt.Printf("                %s\n", strings.Join(sans, ", "))
	}

	if len(cert.CRLDistributionPoints) > 0 {
		fmt.Println("            X509v3 CRL Distribution Points:")
		fmt.Println("                Full Name:")
		for _, crl := range cert.CRLDistributionPoints {
			fmt.Printf("                  URI:%s\n", crl)
		}
	}
}

func formatKeyUsage(usage x509.KeyUsage) string {
	var usages []string
	if usage&x509.KeyUsageDigitalSignature != 0 {
		usages = append(usages, "Digital Signature")
	}
	if usage&x509.KeyUsageKeyEncipherment != 0 {
		usages = append(usages, "Key Encipherment")
	}
	if usage&x509.KeyUsageCertSign != 0 {
		usages = append(usages, "Certificate Sign")
	}
	if usage&x509.KeyUsageCRLSign != 0 {
		usages = append(usages, "CRL Sign")
	}
	return strings.Join(usages, ", ")
}

func formatExtKeyUsage(usages []x509.ExtKeyUsage) string {
	var names []string
	for _, u := range usages {
		switch u {
		case x509.ExtKeyUsageServerAuth:
			names = append(names, "Server Authentication")
		case x509.ExtKeyUsageClientAuth:
			names = append(names, "Client Authentication")
		default:
			names = append(names, fmt.Sprintf("Unknown (%d)", u))
		}
	}
	return strings.Join(names, ", ")
}

func formatKeyID(id []byte) string {
	var parts []string
	for _, b := range id {
		parts = append(parts, fmt.Sprintf("%02X", b))
	}
	return strings.Join(parts, ":")
}

func printSignature(sig []byte) {
	hexStr := hex.EncodeToString(sig)
	for i := 0; i < len(hexStr); i += 36 {
		end := i + 36
		if end > len(hexStr) {
			end = len(hexStr)
		}
		line := hexStr[i:end]
		var formatted []string
		for j := 0; j < len(line); j += 2 {
			formatted = append(formatted, line[j:j+2])
		}
		fmt.Printf("         %s\n", strings.Join(formatted, ":"))
	}
}
