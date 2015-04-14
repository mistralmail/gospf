package main

import (
	"github.com/gopistolet/gospf/dns"
)

func main() {

	dns := dns.GoSPFDNS{}
	dns.GetSPFRecord("uantwerpen.be")

}
