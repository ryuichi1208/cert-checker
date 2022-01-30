package accept

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"os"
	"time"
)

type CertChecker struct {
	host       string
	servername string
	port       int
	insecure   bool
}

var tlsSuit = map[string]uint16{
	"TLS_RSA_WITH_RC4_128_SHA":                0x0005,
	"TLS_RSA_WITH_3DES_EDE_CBC_SHA":           0x000a,
	"TLS_RSA_WITH_AES_128_CBC_SHA":            0x002f,
	"TLS_RSA_WITH_AES_256_CBC_SHA":            0x0035,
	"TLS_RSA_WITH_AES_128_CBC_SHA256":         0x003c,
	"TLS_RSA_WITH_AES_128_GCM_SHA256":         0x009c,
	"TLS_RSA_WITH_AES_256_GCM_SHA384":         0x009d,
	"TLS_ECDHE_ECDSA_WITH_RC4_128_SHA":        0xc007,
	"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA":    0xc009,
	"TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA":    0xc00a,
	"TLS_ECDHE_RSA_WITH_RC4_128_SHA":          0xc011,
	"TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA":     0xc012,
	"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA":      0xc013,
	"TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA":      0xc014,
	"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256": 0xc023,
	"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256":   0xc027,
	"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256":   0xc02f,
	"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256": 0xc02b,
	"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384":   0xc030,
	"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384": 0xc02c,
	"TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305":    0xcca8,
	"TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305":  0xcca9,
}

func getCert(addr string, servername string, insecure bool) *x509.Certificate {
	debug := false
	var tlsSuites []uint16
	for _, v := range tlsSuit {
		tlsSuites = append(tlsSuites, v)
	}
	cfg := &tls.Config{
		ServerName:         servername,
		MinVersion:         tls.VersionTLS11,
		MaxVersion:         tls.VersionTLS12,
		CipherSuites:       tlsSuites,
		InsecureSkipVerify: insecure,
	}

	conn, err := tls.Dial("tcp", addr, cfg)
	if err != nil {
		panic(err)
	}
	defer conn.Close()
	certs := conn.ConnectionState().PeerCertificates

	if len(certs) < 1 {
		panic("no certifiations are available")
	}

	cert := certs[0]
	if debug {
		fmt.Println(cert)
	}
	for _, c := range certs[1:] {
		if c.NotAfter.Before(cert.NotAfter) {
			cert = c
		}
	}
	return cert
}

var (
	servername string
	host       string
	port       int
)

func (cck *CertChecker) initCommand(args []string) {
	flag.CommandLine.Init("cert-checkr", flag.ContinueOnError)
	flag.StringVar(&cck.servername, "s", "", "server name")
	flag.StringVar(&cck.host, "h", "", "host (servername or IP address)")
	flag.IntVar(&cck.port, "p", 0, "port number")
	flag.BoolVar(&cck.insecure, "k", false, "insecure flag")
	if err := flag.CommandLine.Parse(args[1:]); err != nil {
		if err != flag.ErrHelp {
			fmt.Fprintf(os.Stderr, "error: %s\n", err)
		}
		os.Exit(2)
	}
}

func Run(args []string) {
	cck := new(CertChecker)
	cck.initCommand(args)
	addr := fmt.Sprintf("%s:%d", cck.host, cck.port)
	cert := getCert(addr, cck.servername, cck.insecure)
	expiry := cert.NotAfter
	dur := expiry.Sub(time.Now())
	days := int(dur.Hours() / 24)
	dayMsg := fmt.Sprintf("%d ", days)
	if days == 1 {
		dayMsg += "day"
	} else {
		dayMsg += "days"
	}
	msg := fmt.Sprintf("%s:%s expires in %s (%s)", addr, cck.servername, dayMsg, expiry)
	fmt.Println(msg)
}
