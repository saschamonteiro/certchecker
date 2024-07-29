package main

import (
	"embed"
	"flag"
	"fmt"
	"os"

	"github.com/saschamonteiro/certchecker/internal/app"
)

//go:embed *.tmpl
var Assets embed.FS

var sha1ver string
var buildTime string

func main() {

	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "Cert Checker git-sha1:%v buildtime:%v\n", sha1ver, buildTime)
		fmt.Fprintf(flag.CommandLine.Output(), "Usage information:\n")
		flag.PrintDefaults()
	}

	cidrAddressList := flag.String("cidr", "192.168.10.0/24,192.168.11.0/24", "network cidr list")
	portList := flag.String("ports", "443,636,587,8443", "tcp port list")
	skipNoDnsFound := flag.Bool("skipnodns", false, "skip no dns found")
	htmlOut := flag.String("html", "", "html output file")
	jsonOut := flag.String("json", "", "json output file")
	concurrent := flag.Int("conc", 512, "concurrent connections")
	debug := flag.Bool("debug", false, "debug")
	dialTimeout := flag.Int("t", 3, "dial timeout in seconds")
	ver := flag.Bool("v", false, "version")
	flag.Parse()
	if *ver {
		fmt.Printf("version: %s\n", sha1ver)
		fmt.Printf("build time: %s\n", buildTime)
		os.Exit(0)
	}
	appProps := app.AppProps{
		CidrAddressList: *cidrAddressList,
		PortList:        *portList,
		SkipNoDnsFound:  *skipNoDnsFound,
		Assets:          Assets,
		HtmlOut:         *htmlOut,
		JsonOut:         *jsonOut,
		Concurrent:      *concurrent,
		Debug:           *debug,
		DialTimeout:     *dialTimeout,
	}

	app.StartTlsCollect(appProps)

}
