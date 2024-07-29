// package app holds the application business logic
package app

import (
	"context"
	"embed"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/saschamonteiro/certchecker/internal/certs"
	"github.com/saschamonteiro/certchecker/internal/output"
	"golang.org/x/sync/errgroup"
)

type AppProps struct {
	CidrAddressList string
	PortList        string
	SkipNoDnsFound  bool
	Assets          embed.FS
	HtmlOut         string
	JsonOut         string
	Concurrent      int
	Debug           bool
	DialTimeout     int
}

// StartTlsCollect will start the scan for TLS certificates on the specified networks/ports
func StartTlsCollect(app AppProps) {
	cidrAdd := strings.Split(app.CidrAddressList, ",")
	allHosts := []string{}
	for _, cidrAddress := range cidrAdd {
		hosts, _ := hostsFromCIDR(cidrAddress)
		allHosts = append(allHosts, hosts...)
	}
	ports := strings.Split(app.PortList, ",")
	g, ctx := errgroup.WithContext(context.Background())
	resultChan := make(chan []certs.TlsCert, len(allHosts)*len(ports))
	result := make([]certs.TlsCert, 0)
	g.SetLimit(app.Concurrent)
	if len(allHosts) > 1024 {
		fmt.Printf("WARNING: this may be too many hosts (%v) to scan due to ARP thresholds\n", len(allHosts))
	}
	fmt.Printf("Scanning CIDRs:%v [hosts:%v] [ports:%s], please wait ", app.CidrAddressList, len(allHosts), app.PortList)
	start := time.Now()
	for _, host := range allHosts {
		a := host
		g.Go(func() error {
			cres := findHostCerts(a, ports, app.SkipNoDnsFound, app.Debug, app.DialTimeout)
			select {
			case resultChan <- cres:
			case <-ctx.Done():
				return context.Canceled
			default:
			}
			return nil
		})
	}
	if err := g.Wait(); err != nil {
		fmt.Printf("ERROR: %+v\n", err)
		return
	}

	close(resultChan)
	for val := range resultChan {
		result = append(result, val...)
	}
	duration := time.Since(start).Round(time.Second)
	fmt.Printf("\nFound %v TLS Certs in %v\n", len(result), duration)
	sort.Slice(result, func(i, j int) bool { return result[i].Expiry.Before(result[j].Expiry) })

	output.ShowCertTable(result)

	if app.HtmlOut != "" {
		output.CreateOutFile(result, app.HtmlOut, "certs_html.tmpl", app.Assets)
	}
	if app.JsonOut != "" {
		output.CreateJsonFile(result, app.JsonOut)
	}
}

// findHostCerts will scan a host for TLS certs
func findHostCerts(ip string, ports []string, skipNoDnsFound bool, debug bool, dialTimeout int) []certs.TlsCert {
	serveraddr, err := net.LookupAddr(ip)
	cres := []certs.TlsCert{}
	if err == nil && len(serveraddr) > 0 {
		serverN := strings.TrimRight(serveraddr[0], ".")
		for _, port := range ports {
			c := certs.CheckCert(serverN, port, ip, debug, dialTimeout)
			if c.Issuer != "" {
				cres = append(cres, c)
			}
		}
	} else {
		if skipNoDnsFound {
			return nil
		}
		for _, port := range ports {
			c := certs.CheckCert(ip, port, ip, debug, dialTimeout)
			if c.Issuer != "" {
				cres = append(cres, c)
			}
		}
	}
	// fmt.Printf("Host[%s] certs[%v]\n", ip, len(cres))
	return cres
}

// hostsFromCIDR will return a list of hosts from a CIDR
func hostsFromCIDR(cidr string) ([]string, error) {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}
	var ips []string
	for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); inc(ip) {
		ips = append(ips, ip.String())
	}
	if len(ips) == 1 {
		return ips, nil
	}
	return ips[1 : len(ips)-1], nil
}

// inc will increment an IP
func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}
