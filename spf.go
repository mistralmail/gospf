package main

import (
	"github.com/gopistolet/gospf/dns"
	"net"
)

type SPF struct {
	Pass     []net.IPNet // IPs that pass
	Neutral  []net.IPNet // IPs that are neutral
	SoftFail []net.IPNet // IP's that fail weakly
	Fail     []net.IPNet // IP's that fail
	All      string      // qualifier of 'all' directive

	dns        dns.DnsResolver
	directives Directives
	modifiers  Modifiers
}

// NewSPF creates a new SPF instance
// fully loaded with all the SPF directives
// (so no more DNS lookups must be done after constructing the instance)
func NewSPF(domain string, dns_resolver dns.DnsResolver) (*SPF, error) {
	spf := SPF{
		Pass:     make([]net.IPNet, 0),
		Neutral:  make([]net.IPNet, 0),
		SoftFail: make([]net.IPNet, 0),
		Fail:     make([]net.IPNet, 0),
	}

	spf.dns = dns_resolver

	record, err := spf.dns.GetSPFRecord(domain)
	if err != nil {
		return nil, err
	}
	directives, modifiers, err := getTerms(record)
	if err != nil {
		return nil, err
	}
	spf.directives = Directives(directives)
	spf.modifiers = Modifiers(modifiers)

	return &spf, nil
}

func (spf *SPF) handleDirectives() error {

	for _, directive := range spf.directives {

		switch directive.Mechanism {
		case "all":
			{
				/*
					RFC 7208 5.1
						The "all" mechanism is a test that always matches.  It is used as the
						rightmost mechanism in a record to provide an explicit default.

						For example:

						   v=spf1 a mx -all
				*/
				spf.All = directive.Qualifier

				/*
					Mechanisms after "all" will never be tested.  Mechanisms listed after
					"all" MUST be ignored.  Any "redirect" modifier (Section 6.1) MUST be
					ignored when there is an "all" mechanism in the record, regardless of
					the relative ordering of the terms.
				*/
				break
			}
		case "include":
			{
				/*
					RFC 7208 5.2
						include          = "include"  ":" domain-spec

						The "include" mechanism triggers a recursive evaluation of
						check_host().
				*/
			}
		case "a":
			{
				/*
					RFC 7208 5.3
						This mechanism matches if <ip> is one of the <target-name>'s IP
						addresses.  For clarity, this means the "a" mechanism also matches
						AAAA records.

						a                = "a"      [ ":" domain-spec ] [ dual-cidr-length ]

						An address lookup is done on the <target-name> using the type of
						lookup (A or AAAA) appropriate for the connection type (IPv4 or
						IPv6).  The <ip> is compared to the returned address(es).  If any
						address matches, the mechanism matches.
				*/
			}
		case "mx":
			{
				/*
					RFC 7208 5.4
						This mechanism matches if <ip> is one of the MX hosts for a domain
						name.

						mx               = "mx"     [ ":" domain-spec ] [ dual-cidr-length ]

						check_host() first performs an MX lookup on the <target-name>.  Then
						it performs an address lookup on each MX name returned.  The <ip> is
						compared to each returned IP address.  To prevent denial-of-service
						(DoS) attacks, the processing limits defined in Section 4.6.4 MUST be
						followed.  If the MX lookup limit is exceeded, then "permerror" is
						returned and the evaluation is terminated.  If any address matches,
						the mechanism matches.

						Note regarding implicit MXes: If the <target-name> has no MX record,
						check_host() MUST NOT apply the implicit MX rules of [RFC5321] by
						querying for an A or AAAA record for the same name.
				*/
			}
		case "ptr":
			{
				// not (yet) supported
				/*
					RFC 7208 5.5
						This mechanism tests whether the DNS reverse-mapping for <ip> exists
						and correctly points to a domain name within a particular domain.
						This mechanism SHOULD NOT be published.  See the note at the end of
						this section for more information.
				*/
			}
		case "ip4":
			{
				/*
					RFC 7208 5.6
						These mechanisms test whether <ip> is contained within a given
						IP network.

						ip4  = "ip4"   ":" ip4-network   [ ip4-cidr-length ]
						ip4-cidr-length  = "/" ("0" / %x31-39 0*1DIGIT) ; value range 0-32
				*/
			}
		case "ip6":
			{
				/*
					ip6  = "ip6"   ":" ip6-network   [ ip6-cidr-length ]
					ip6-cidr-length  = "/" ("0" / %x31-39 0*2DIGIT) ; value range 0-128
				*/
			}
		case "exists":
			{
				/*
					RFC 7208 5.7
						The resulting domain name is used for a DNS A RR lookup
						(even when the connection type is IPv6).
						If any A record is returned, this mechanism matches.
				*/

			}
		default:
			{

			}
		}

	}

	return nil

}

/*
CheckIP checks if the given IP is a valid sender
(returns answers following section 2.6 from RFC 7208)

	RFC 7208: 2.6.  Results of Evaluation:

	2.6.1.  None

	   A result of "none" means either (a) no syntactically valid DNS domain
	   name was extracted from the SMTP session that could be used as the
	   one to be authorized, or (b) no SPF records were retrieved from
	   the DNS.

	2.6.2.  Neutral

	   A "neutral" result means the ADMD has explicitly stated that it is
	   not asserting whether the IP address is authorized.

	2.6.3.  Pass

	   A "pass" result is an explicit statement that the client is
	   authorized to inject mail with the given identity.

	2.6.4.  Fail

	   A "fail" result is an explicit statement that the client is not
	   authorized to use the domain in the given identity.

	2.6.5.  Softfail

	   A "softfail" result is a weak statement by the publishing ADMD that
	   the host is probably not authorized.  It has not published a
	   stronger, more definitive policy that results in a "fail".

	2.6.6.  Temperror

	   A "temperror" result means the SPF verifier encountered a transient
	   (generally DNS) error while performing the check.  A later retry may
	   succeed without further DNS operator action.

	2.6.7.  Permerror

	   A "permerror" result means the domain's published records could not
	   be correctly interpreted.  This signals an error condition that
	   definitely requires DNS operator intervention to be resolved.
*/
func (spf *SPF) CheckIP(net.IP) string {
	return "None"
}
