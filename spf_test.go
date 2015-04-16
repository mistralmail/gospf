package gospf

import (
	_ "fmt"
	. "github.com/smartystreets/goconvey/convey"
	"net"
	"testing"
)

func TestHandleIPNets(t *testing.T) {
	Convey("Testing handleIPNets()", t, func() {

		ips := []string{"69.208.0.0", "1.1.1.1"}
		ip_net, err := GetRanges(ips, "", "")
		So(err, ShouldEqual, nil)
		spf := SPF{}
		spf.handleIPNets(ip_net, "+")
		So(len(spf.Pass), ShouldEqual, 2)
		spf.handleIPNets(ip_net, "?")
		So(len(spf.Neutral), ShouldEqual, 2)
		spf.handleIPNets(ip_net, "~")
		So(len(spf.SoftFail), ShouldEqual, 2)
		spf.handleIPNets(ip_net, "-")
		So(len(spf.Fail), ShouldEqual, 2)

	})
}

func TestAddressRanges(t *testing.T) {

	Convey("Testing GetRanges()", t, func() {
		//ips []string, ip4_cidr string, ip6_cidr string) ([]net.IPNet
		tests := []struct {
			ips            []string
			ip4_cidr       string
			ip6_cidr       string
			shouldMatch    []string
			shouldNotMatch []string
		}{
			// IPv4
			{
				ips:            []string{"69.208.0.0"},
				ip4_cidr:       "24",
				shouldMatch:    []string{"69.208.0.0", "69.208.0.127", "69.208.0.255"},
				shouldNotMatch: []string{"69.208.1.0", "69.11.0.0", "13.208.0.0", "0.0.0.0"},
			},
			{
				ips:            []string{"192.168.1.1"},
				ip4_cidr:       "32",
				shouldMatch:    []string{"192.168.1.1"},
				shouldNotMatch: []string{"192.168.1.0", "192.168.1.2"},
			},
			{
				ips:            []string{"192.168.1.1"},
				ip4_cidr:       "",
				shouldMatch:    []string{"192.168.1.1"},
				shouldNotMatch: []string{"192.168.1.0", "192.168.1.2"},
			},
			{
				ips:         []string{"192.168.1.1"},
				ip4_cidr:    "0",
				shouldMatch: []string{"1.1.1.1", "4.5.6.7", "192.168.1.1"},
			},
			// IPv6
			{
				ips:         []string{"0::0"},
				ip6_cidr:    "0",
				shouldMatch: []string{"::", "2a01:67e0::10", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"},
			},
			{
				ips:         []string{"2000::"},
				ip6_cidr:    "8",
				shouldMatch: []string{"2000::", "2001:db8:0::1", "20ff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"},
			},
			{
				ips:            []string{"2001:db8::"},
				ip6_cidr:       "128",
				shouldMatch:    []string{"2001:db8::"},
				shouldNotMatch: []string{"2000::", "20ff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"},
			},
		}

		for _, test := range tests {
			ip_net, err := GetRanges(test.ips, test.ip4_cidr, test.ip6_cidr)
			So(err, ShouldEqual, nil)
			for _, ip := range test.shouldMatch {
				So(ip_net[0].Contains(net.ParseIP(ip)), ShouldEqual, true)
			}
			for _, ip := range test.shouldNotMatch {
				So(ip_net[0].Contains(net.ParseIP(ip)), ShouldEqual, false)
			}
		}
	})

	Convey("Testing GetRanges() with invalid cidrs", t, func() {
		tests := []struct {
			ips      []string
			ip4_cidr string
			ip6_cidr string
		}{
			{
				ips:      []string{"192.168.1.1"},
				ip4_cidr: "33",
			},
			{
				ips:      []string{"192.168.1.1"},
				ip4_cidr: "-1",
			},
			{
				ips:      []string{"2001:db8::"},
				ip6_cidr: "-1",
			},
			{
				ips:      []string{"2001:db8::"},
				ip6_cidr: "129",
			},
			{
				ips: []string{"2001:db8:0:1"}, //invalid IPv6 address
			},
			{
				ips: []string{"20001:db8:0:1"}, //invalid IPv6 address
			},
			{
				ips: []string{"192.168.1.1.1.1.1"}, //invalid IPv4 address
			},
			{
				ips: []string{"1921.168.1.1"}, //invalid IPv4 address
			},
		}

		for _, test := range tests {
			_, err := GetRanges(test.ips, test.ip4_cidr, test.ip6_cidr)
			So(err, ShouldNotEqual, nil)
		}
	})

}
