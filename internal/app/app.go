package app

import (
	"context"
	"embed"
	"fmt"
	"net"
	"sort"
	"strings"

	"github.com/saschamonteiro/certchecker/internal/certs"
	"github.com/saschamonteiro/certchecker/internal/output"
	"golang.org/x/sync/errgroup"
)

func StartTlsCollect(cidrAddressList string, portList string, skipNoDnsFound bool, Assets embed.FS, htmlOut string, jsonOut string) {
	cidrAdd := strings.Split(cidrAddressList, ",")
	allHosts := []string{}
	for _, cidrAddress := range cidrAdd {
		hosts, _ := hostsFromCIDR(cidrAddress)
		allHosts = append(allHosts, hosts...)
	}
	ports := strings.Split(portList, ",")
	g, ctx := errgroup.WithContext(context.Background())
	resultChan := make(chan []certs.TlsCert, len(allHosts)*len(ports))
	result := make([]certs.TlsCert, 0)
	g.SetLimit(128)
	fmt.Printf("Scanning CIDRs:%v [ports:%s], please wait ", cidrAddressList, portList)
	for _, host := range allHosts {
		a := host
		g.Go(func() error {
			cres := findHostCerts(a, ports, skipNoDnsFound)
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
	fmt.Printf("\nFound %v TLS Certs\n", len(result))
	sort.Slice(result, func(i, j int) bool { return result[i].Expiry.Before(result[j].Expiry) })

	output.ShowCertTable(result)

	if htmlOut != "" {
		output.CreateOutFile(result, htmlOut, "certs_html.tmpl", Assets)
	}
	if jsonOut != "" {
		output.CreateJsonFile(result, jsonOut)
	}
}

func findHostCerts(ip string, ports []string, skipNoDnsFound bool) []certs.TlsCert {
	serveraddr, err := net.LookupAddr(ip)
	cres := []certs.TlsCert{}
	if err == nil && len(serveraddr) > 0 {
		serverN := strings.TrimRight(serveraddr[0], ".")
		for _, port := range ports {
			c := certs.CheckCert(serverN, port, ip)
			if c.Issuer != "" {
				cres = append(cres, c)
			}
		}
	} else {
		if skipNoDnsFound {
			return nil
		}
		for _, port := range ports {
			c := certs.CheckCert(ip, port, ip)
			if c.Issuer != "" {
				cres = append(cres, c)
			}
		}
	}
	return cres
}

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

func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}
