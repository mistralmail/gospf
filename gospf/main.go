package main

import (
	"fmt"
	_ "net"
	"os"

	"github.com/mistralmail/gospf"
	"github.com/mistralmail/gospf/dns"
)

func main() {

	fmt.Println("\nGoSPF")
	fmt.Printf("-----\n")

	if len(os.Args) < 3 {
		fmt.Println("Usage: " + os.Args[0] + " domain ip [debug]")
		return
	}

	domain := os.Args[1]

	spf, err := gospf.New(domain, &dns.GoSPFDNS{})
	if err != nil {
		fmt.Println(err)
		return
	}

	if len(os.Args) >= 4 && os.Args[3] == "debug" {
		fmt.Print(spf)
		fmt.Printf("\n-----\n")
	}

	ip := os.Args[2]
	check, err := spf.CheckIP(ip)
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Printf(ip, "->", check, "\n")

}
