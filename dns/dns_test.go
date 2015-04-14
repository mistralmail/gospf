package dns

import (
	_ "fmt"
	. "github.com/smartystreets/goconvey/convey"
	"testing"
)

var spfs = []string{
	"v=spf1 a -all",
	"v=spf1 a:mail.example.com -all",
	"v=spf1 ip4:192.0.2.0/24 ip4:198.51.100.123 a -all",
}

func TestIsSPF(t *testing.T) {

	Convey("Testing IsSPF()", t, func() {

		for _, spf := range spfs {
			So(IsSPF(spf), ShouldEqual, true)
		}

	})

}

func TestIsSupportedProtocol(t *testing.T) {

	Convey("Testing IsSPF()", t, func() {

		for _, spf := range spfs {
			So(IsSupportedProtocol(spf), ShouldEqual, true)
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
