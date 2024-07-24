[![Go Build Cert Checker](https://github.com/saschamonteiro/certchecker/actions/workflows/go.yml/badge.svg)](https://github.com/saschamonteiro/certchecker/actions/workflows/go.yml)
# Cert Checker / TLS Scan

A utility to scan for TLS certificates in a network segment in CIDR format to quickly find expired certificates.  

This is written in GO and the assets are currently only build for Linux amd64.  

The concurrency for host cert checking is currently set to 128.

## Usage
### Linux amd64
```
#single subnet, single port, output to console only
./certchecker_linux -cidr=10.10.10.0/24 -ports=443 

#single subnet, single port, output to console and html file
./certchecker_linux -cidr=10.10.10.0/24 -ports=443 -html=certs.html

#single subnet, single port, output to console and json file
./certchecker_linux -cidr=10.10.10.0/24 -ports=443 -json=certs.json

#multiple subnets, multiple ports, output to console only
./certchecker_linux -cidr=10.10.10.0/24,10.10.20.0/24 -ports=443,8443
```
## Output
### Console
The certificates will be shown in a table like so  
║ HostIP:Port │ HostDNS (reverse) │ DNS Match Cert │ SNI Verified │ CertDNSNames │ Subject Common Name │ Issuer  │ Expiry ↓ │ Expired ║


## Build
### Build binary for your local architecture
```
go build -ldflags "-s -w -X main.sha1ver=`git rev-parse HEAD` -X main.buildTime=`date +'%Y-%m-%d_%T%Z'`" -o certchecker main.go
```