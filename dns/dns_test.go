package dns

import (
	_ "fmt"
	"testing"

	. "github.com/smartystreets/goconvey/convey"
)

var validSpfs = []string{
	"v=spf1 a -all",
	"v=spf1 a:mail.example.com -all",
	"v=spf1 ip4:192.0.2.0/24 ip4:198.51.100.123 a -all",
}

var invalidSpfs = []string{
	"",
	"abv=spf",
	"abda=v=spf1",
}

func TestIsSPF(t *testing.T) {
	Convey("Testing IsSPF()", t, func() {
		for _, spf := range validSpfs {
			So(IsSPF(spf), ShouldEqual, true)
		}

		for _, spf := range invalidSpfs {
			So(IsSPF(spf), ShouldEqual, false)
		}
	})

}

func TestIsSupportedProtocol(t *testing.T) {

	Convey("Testing IsSupportedProtocol()", t, func() {

		for _, spf := range validSpfs {
			So(IsSupportedProtocol(spf), ShouldEqual, true)
		}

		for _, spf := range invalidSpfs {
			So(IsSupportedProtocol(spf), ShouldEqual, false)
		}
	})
}

func TestLiveDomains(t *testing.T) {

	if testing.Short() {
		t.Skip("skipping test to avoid external network")
	}

	Convey("Testing live domains", t, func() {

		domains := []string{
			"google.com",
			"hotmail.com",
			"yahoo.com",
		}

		for _, domain := range domains {
			dns := GoSPFDNS{}
			_, err := dns.GetSPFRecord(domain)
			So(err, ShouldEqual, nil)
		}

	})

}
