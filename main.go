package main

import (
	"fmt"
	"github.com/gopistolet/gospf/dns"
	_ "net"
	"os"
)

func main() {

	fmt.Println("\nGoSPF")
	fmt.Println("-----")

	if len(os.Args) < 2 {
		return
	}

	domain := os.Args[1]

	spf, err := NewSPF(domain, &dns.GoSPFDNS{})
	if err != nil {
		fmt.Println(err)
		return
	}

	err = spf.handleDirectives()
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Print(spf)

}
