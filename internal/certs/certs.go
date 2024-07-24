// package certs holds the functions related to TLS certificates
package certs

import (
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"time"
)

// TlsCert holds the data for a TLS certificate
type TlsCert struct {
	HostNameVerified bool      `json:"hostnameVerified"`
	SubjectCN        string    `json:"subjectCN"`
	DNSNames         string    `json:"dnsNames"`
	IPAddresses      string    `json:"ipAddresses"`
	Issuer           string    `json:"issuer"`
	Expiry           time.Time `json:"expiry"`
	Expired          bool      `json:"expired"`
	HostDNS          string    `json:"hostDNS"`
	HostIP           string    `json:"hostIP"`
	HostPort         string    `json:"hostPort"`
	SNIVerified      bool      `json:"sniVerified"`
}

// CheckCert will connect to the host and check if the certificate is valid
func CheckCert(server, port, ip string) TlsCert {
	hostnameVerified := false
	SNIVerified := false
	conf := &tls.Config{InsecureSkipVerify: false}
	if server != ip {
		conf.ServerName = server
	}
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 1 * time.Second}, "tcp", ip+":"+port, conf)
	if err != nil {
		conn, err = tls.DialWithDialer(&net.Dialer{Timeout: 1 * time.Second}, "tcp", ip+":"+port, &tls.Config{InsecureSkipVerify: true})
		if err != nil {
			if strings.Contains(err.Error(), "network is unreachable") || strings.Contains(err.Error(), "i/o timeout") || strings.Contains(err.Error(), "connection refused") || strings.Contains(err.Error(), "no such host") || strings.Contains(err.Error(), "no route to host") {
				return TlsCert{}
			} else {
				fmt.Printf("Server doesn't support SSL certificate err: %v\n", err.Error())
			}
			return TlsCert{}
		} else {
			if strings.Split(server, ":")[0] == conn.ConnectionState().PeerCertificates[0].Subject.CommonName {
				hostnameVerified = true
			} else {
				for _, dns := range conn.ConnectionState().PeerCertificates[0].DNSNames {
					if strings.Split(server, ":")[0] == dns {
						hostnameVerified = true
					}
				}
			}
		}
	} else {

		err = conn.VerifyHostname(strings.Split(server, ":")[0])
		if err != nil {
			fmt.Printf("Hostname doesn't match with certificate: %v\n", err.Error())
		} else {
			hostnameVerified = true
			SNIVerified = true
		}

	}
	expiry := conn.ConnectionState().PeerCertificates[0].NotAfter
	expired := expiry.Before(time.Now())
	cert := TlsCert{
		HostNameVerified: hostnameVerified,
		SubjectCN:        conn.ConnectionState().PeerCertificates[0].Subject.CommonName,
		DNSNames:         fmt.Sprintf("%s", conn.ConnectionState().PeerCertificates[0].DNSNames),
		IPAddresses:      fmt.Sprintf("%s", conn.ConnectionState().PeerCertificates[0].IPAddresses),
		Issuer:           conn.ConnectionState().PeerCertificates[0].Issuer.String(),
		Expiry:           expiry,
		Expired:          expired,
		HostDNS:          server,
		HostIP:           ip,
		HostPort:         port,
		SNIVerified:      SNIVerified,
	}
	if ip == server {
		cert.HostDNS = "-"
	}
	fmt.Printf(".")
	return cert
}
