package main

import (
	"fmt"
	"github.com/gopistolet/gospf/dns"
	"github.com/gopistolet/gospf"
	_ "net"
	"os"
)

func main() {

	fmt.Println("\nGoSPF")
	fmt.Println("-----\n")

	if len(os.Args) < 3 {
		fmt.Println("Usage: " + os.Args[0] + " domain ip [debug]")
		return
	}

	domain := os.Args[1]

	spf, err := gospf.NewSPF(domain, &dns.GoSPFDNS{})
	if err != nil {
		fmt.Println(err)
		return
	}

	if len(os.Args) >= 4 && os.Args[3] == "debug" {
		fmt.Print(spf)
		fmt.Println("\n-----\n")
	}

	ip := os.Args[2]
	check, err := spf.CheckIP(ip)
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Println(ip, "->", check, "\n")

}
