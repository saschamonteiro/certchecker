// package output holds the output logic
package output

import (
	"embed"
	"encoding/json"
	"fmt"
	"os"
	"text/template"
	"time"

	"github.com/alexeyco/simpletable"
	"github.com/saschamonteiro/certchecker/internal/certs"
)

var (
	colorReset = "\033[0m"
	colorRed   = "\033[31m"
	colorGreen = "\033[32m"
)

// ShowCertTable will print the table to the console
func ShowCertTable(data []certs.TlsCert) {
	table := simpletable.New()
	table.Header = &simpletable.Header{
		Cells: []*simpletable.Cell{
			{Align: simpletable.AlignLeft, Text: "HostIP:Port"},
			{Align: simpletable.AlignLeft, Text: "HostDNS (reverse)"},
			{Align: simpletable.AlignLeft, Text: "DNS Match Cert"},
			{Align: simpletable.AlignLeft, Text: "SNI Verified"},
			{Align: simpletable.AlignLeft, Text: "CertDNSNames"},
			{Align: simpletable.AlignLeft, Text: "Subject Common Name"},
			{Align: simpletable.AlignLeft, Text: "Issuer"},
			{Align: simpletable.AlignLeft, Text: "Expiry ↓"},
			{Align: simpletable.AlignLeft, Text: "Expired"},
		},
	}
	for _, cert := range data {
		table.Body.Cells = append(table.Body.Cells, []*simpletable.Cell{
			{Align: simpletable.AlignLeft, Text: fmt.Sprintf("%s:%s", cert.HostIP, cert.HostPort)},
			{Align: simpletable.AlignLeft, Text: cert.HostDNS},
			{Align: simpletable.AlignLeft, Text: valid(cert.HostNameVerified)},
			{Align: simpletable.AlignLeft, Text: valid(cert.SNIVerified)},
			{Align: simpletable.AlignLeft, Text: truncateText(cert.DNSNames, 20)},
			{Align: simpletable.AlignLeft, Text: cert.SubjectCN},
			{Align: simpletable.AlignLeft, Text: truncateText(cert.Issuer, 30)},
			{Align: simpletable.AlignLeft, Text: cert.Expiry.Local().String()},
			{Align: simpletable.AlignLeft, Text: exp(cert.Expired)},
		})
	}
	table.SetStyle(simpletable.StyleUnicode)
	fmt.Println(table.String())
}

// TlsPageData holds the data for the html page
type TlsPageData struct {
	TlsCerts []certs.TlsCert
}

// CreateOutFile will create the output file
func CreateOutFile(data []certs.TlsCert, fileName string, templateFile string, Assets embed.FS) {
	t, _ := template.ParseFS(Assets, templateFile)
	f, err := os.Create(fileName)
	if err != nil {
		fmt.Println("error create file: ", err)
		return
	}
	defer f.Close()
	err = t.Execute(f, TlsPageData{
		TlsCerts: data,
	})
	if err != nil {
		fmt.Printf("error execute template: %v\n", err)
		return
	}
	fmt.Printf("Output file created: %s\n", fileName)
}

// JsonMeta holds the metadata
type JsonMeta struct {
	Certs    []certs.TlsCert `json:"certs"`
	DateTime time.Time       `json:"dateTime"`
}

// CreateJsonFile will create the json file
func CreateJsonFile(data []certs.TlsCert, fileName string) {
	f, err := os.Create(fileName)
	if err != nil {
		fmt.Println("error create file: ", err)
		return
	}
	defer f.Close()
	meta := JsonMeta{
		Certs:    data,
		DateTime: time.Now(),
	}
	jsonData, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		fmt.Println("error parsing data to json: ", err)
		return
	}
	_, err = f.Write(jsonData)
	if err != nil {
		fmt.Println("error writing data to file: ", err)
		return
	}
	fmt.Printf("Output file created: %s\n", fileName)
}

// exp formats the expired status
func exp(s bool) string {
	if s {
		return fmt.Sprintf("%s%v%s", colorRed, s, colorReset)
	}
	return fmt.Sprintf("%s%v%s", colorGreen, s, colorReset)
}

// valid formats the valid status
func valid(s bool) string {
	if !s {
		return fmt.Sprintf("%s%v%s", colorRed, s, colorReset)
	}
	return fmt.Sprintf("%s%v%s", colorGreen, s, colorReset)
}

// truncateText will truncate the text to given size
func truncateText(s string, max int) string {
	if max >= len(s) {
		return s
	}
	return s[:max] + "..."
}
