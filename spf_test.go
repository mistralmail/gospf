package gospf

import (
	"fmt"
	. "github.com/smartystreets/goconvey/convey"
	"net"
	"testing"

	"github.com/gopistolet/gospf/dns"
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

func TestSimpleSPFLookup(t *testing.T) {
	tests := []SPFTestParams{
		{
			Domain: "simple.example.com",
			IP:     "1.2.3.4",
			Want:   "Pass",
		},
		{
			Domain: "simple.example.com",
			IP:     "1.2.3.5",
			Want:   "Fail",
		},
	}
	runSPFTest("Testing simple spf lookup", t, tests)
}

func runSPFTest(testName string, t *testing.T, tests []SPFTestParams) {
	Convey(testName, t, func() {
		testResolver := &TestResolver{}
		for _, test := range tests {
			spf, err := New(test.Domain, testResolver)
			if err != nil {
				So(err.Error(), ShouldEqual, test.Want)
				continue
			}
			check, err := spf.CheckIP(test.IP)
			if err != nil {
				So(err.Error(), ShouldEqual, test.Want)
				continue
			}
			So(check, ShouldEqual, test.Want)
		}
	})
}

// Fixtures for SPF processing and recursion

type SPFTestParams struct {
	Domain string
	IP     string
	Want   string
}

var txtRecords = map[string][]string{
	"simple.example.com": []string{"v=spf1 ip4:1.2.3.4 -all"},
	"example.com":        []string{"v=spf1 include:_spf.example.com ~all"},
	"_spf.example.com": []string{"v=spf1 include:spf1.example.com" +
		"include:spf2.example.com" +
		"include:spf3.example.com"},
	"spf1.example.com":            []string{"v=spf1 ip4:1.1.1.1/24 ~all"},
	"spf2.example.com":            []string{"v=spf1 ip4:1.1.1.2/24 ip4:1.1.1.3/24 ip4:1.1.1.4/24 ~all"},
	"spf3.example.com":            []string{"v=spf1 ip6:1111::1/48 ~all"},
	"matchall.example.com":        []string{"v=spf1 ip4:0.0.0.0/0 ip6:0::1/0 -all"},
	"recursive.example.com":       []string{"v=spf1 include:example.com include:recursive.example.com -all"},
	"mx-check.example.com":        []string{"v=spf1 mx:example.com ~all"},
	"redirect.example.com":        []string{"v=spf1 redirect:example.com"},
	"ignore-redirect.example.com": []string{"v=spf1 redirect:example.com -all"},
}

var mxRecords = map[string][]*net.MX{
	"example.com": []*net.MX{
		&net.MX{Host: "mxa.example.com", Pref: 10},
		&net.MX{Host: "mxb.example.com", Pref: 10},
	},
	"too-many-mx-records.example.com": []*net.MX{
		&net.MX{Host: "mxa.example.com", Pref: 1},
		&net.MX{Host: "mxb.example.com", Pref: 2},
		&net.MX{Host: "mxa.example.com", Pref: 3},
		&net.MX{Host: "mxb.example.com", Pref: 4},
		&net.MX{Host: "mxa.example.com", Pref: 5},
		&net.MX{Host: "mxb.example.com", Pref: 6},
		&net.MX{Host: "mxa.example.com", Pref: 7},
		&net.MX{Host: "mxb.example.com", Pref: 8},
		&net.MX{Host: "mxa.example.com", Pref: 9},
		&net.MX{Host: "mxb.example.com", Pref: 10},
		&net.MX{Host: "mxb.example.com", Pref: 11},
	},
}

var aRecords = map[string][]string{
	"example.com": []string{
		"1.2.3.1",
		"1.2.3.2",
		"1.2.3.3",
		"1.2.3.4",
		"1.2.3.5",
	},
	"mxa.example.com": []string{
		"1.2.3.1",
	},
	"mxb.example.com": []string{
		"1.2.3.2",
	},
	"test.com": []string{
		"10.10.10.1",
	},
	"too-many-a-records.example.com": []string{
		"1.1.1.1",
		"1.1.1.2",
		"1.1.1.3",
		"1.1.1.4",
		"1.1.1.5",
		"1.1.1.6",
		"1.1.1.7",
		"1.1.1.8",
		"1.1.1.9",
		"1.1.1.10",
		"1.1.1.11",
		"1.1.1.12",
	},
}

// Set up test DNS resolver
type TestResolver struct {
}

func (t *TestResolver) GetARecords(domain string) ([]string, error) {
	val, ok := aRecords[domain]
	if !ok {
		return val, fmt.Errorf("%v lookup failed", domain)
	}
	return val, nil
}

func (t *TestResolver) GetMXRecords(domain string) ([]*net.MX, error) {
	val, ok := mxRecords[domain]
	if !ok {
		return val, fmt.Errorf("%v lookup failed", domain)
	}
	return val, nil
}

func (t *TestResolver) GetSPFRecord(domain string) (string, error) {
	records, ok := txtRecords[domain]
	if !ok {
		return "", fmt.Errorf("%v lookup failed", domain)
	}
	for _, record := range records {
		if !dns.IsSPF(record) {
			continue
		}
		if !dns.IsSupportedProtocol(record) {
			return "", fmt.Errorf("Unsupported SPF record: " + record)
		}
		return record, nil
	}
	return "", fmt.Errorf("No SPF record found for " + domain)
}

// end setup of test resolver
