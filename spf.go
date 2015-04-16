package gospf

import (
	"errors"
	"fmt"
	"github.com/gopistolet/gospf/dns"
	"net"
	"strconv"
	"strings"
)

type include struct {
	qualifier string
	spf       *SPF
}

type SPF struct {
	Pass     []net.IPNet // IPs that pass
	Neutral  []net.IPNet // IPs that are neutral
	SoftFail []net.IPNet // IP's that fail weakly
	Fail     []net.IPNet // IP's that fail
	All      string      // qualifier of 'all' directive
	Domain   string
	Includes []include // Processed SPF object of include mechanism
	Redirect *SPF      // Processed SPF object of include mechanism

	dns        dns.DnsResolver
	directives Directives
	modifiers  Modifiers
}

func (spf SPF) String() string {
	return spf.toString("")
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
		Domain:   domain,
		Includes: make([]include, 0),
		Redirect: nil,
		All:      "undefined",
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
	spf.directives.process()
	spf.modifiers = Modifiers(modifiers)
	spf.modifiers.process()

	err = spf.handleDirectives()
	if err != nil {
		return nil, err
	}
	err = spf.handleModifiers()
	if err != nil {
		return nil, err
	}

	return &spf, nil
}

func (spf *SPF) handleIPNets(ips []net.IPNet, qualifier string) {
	/*
		RFC 7208 4.6.2.

			The possible qualifiers, and the results they cause check_host() to
			return, are as follows:

			   "+" pass
			   "-" fail
			   "~" softfail
			   "?" neutral

			The qualifier is optional and defaults to "+".
	*/

	var list *[]net.IPNet
	switch qualifier {
	case "+", "":
		list = &spf.Pass
	case "?":
		list = &spf.Neutral
	case "~":
		list = &spf.SoftFail
	case "-":
		list = &spf.Fail
	default:
		panic("Unknown qualifier")
	}

	*list = append(*list, ips...)
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
			}
		case "include":
			{
				/*
					RFC 7208 5.2
						include          = "include"  ":" domain-spec

						The "include" mechanism triggers a recursive evaluation of
						check_host().
				*/
				if _, ok := directive.Arguments["domain"]; !ok {
					return errors.New("No domain given for include mechanism")
				}
				include_spf, err := NewSPF(directive.Arguments["domain"], spf.dns)
				if err != nil {
					return err
				}
				spf.Includes = append(spf.Includes, include{qualifier: directive.Qualifier, spf: include_spf})
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
				domain := spf.Domain
				if d, ok := directive.Arguments["domain"]; ok && d != "" {
					domain = d
				}
				ips, err := spf.dns.GetARecords(domain)
				if err != nil {
					return err
				}
				ip_nets, err := GetRanges(ips, directive.Arguments["ip4-cidr"], directive.Arguments["ip6-cidr"])
				if err != nil {
					return err
				}
				spf.handleIPNets(ip_nets, directive.Qualifier)
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

					RFC 1035 3.3.9.
						PREFERENCE      A 16 bit integer which specifies the preference given to
										this RR among others at the same owner.  Lower values
										are preferred.

						EXCHANGE        A <domain-name> which specifies a host willing to act as
										a mail exchange for the owner name.
				*/
				domain := spf.Domain
				if d, ok := directive.Arguments["domain"]; ok && d != "" {
					domain = d
				}
				// Get mx records
				mxRecords, err := spf.dns.GetMXRecords(domain)
				if err != nil {
					return err
				}
				// Get A/AAAA records of MX hosts and process them
				for _, mx := range mxRecords {

					ips, err := spf.dns.GetARecords(mx.Host)
					if err != nil {
						return err
					}
					ip_nets, err := GetRanges(ips, directive.Arguments["ip4-cidr"], directive.Arguments["ip6-cidr"])
					if err != nil {
						return err
					}
					spf.handleIPNets(ip_nets, directive.Qualifier)

				}

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
				ips := []string{directive.Arguments["ip"]}
				ip_nets, err := GetRanges(ips, directive.Arguments["ip4-cidr"], directive.Arguments["ip6-cidr"])
				if err != nil {
					return err
				}
				spf.handleIPNets(ip_nets, directive.Qualifier)
			}
		case "ip6":
			{
				/*
					ip6  = "ip6"   ":" ip6-network   [ ip6-cidr-length ]
					ip6-cidr-length  = "/" ("0" / %x31-39 0*2DIGIT) ; value range 0-128
				*/
				ips := []string{directive.Arguments["ip"]}
				ip_nets, err := GetRanges(ips, directive.Arguments["ip4-cidr"], directive.Arguments["ip6-cidr"])
				if err != nil {
					return err
				}
				spf.handleIPNets(ip_nets, directive.Qualifier)
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

func (spf *SPF) handleModifiers() error {

	for _, modifier := range spf.modifiers {

		switch modifier.Key {
		case "redirect":
			{
				/*
					RFC 7208 6.1.
						The "redirect" modifier is intended for consolidating both
						authorizations and policy into a common set to be shared within a
						single ADMD.  It is possible to control both authorized hosts and
						policy for an arbitrary number of domains from a single record.

						redirect         = "redirect" "=" domain-spec

						If all mechanisms fail to match, and a "redirect" modifier is
						present, then processing proceeds as follows:

						The <domain-spec> portion of the redirect section is expanded as per
						the macro rules in Section 7.  Then check_host() is evaluated with
						the resulting string as the <domain>.  The <ip> and <sender>
						arguments remain the same as in the current evaluation of
						check_host().

						The result of this new evaluation of check_host() is then considered
						the result of the current evaluation with the exception that if no
						SPF record is found, or if the <target-name> is malformed, the result
						is a "permerror" rather than "none".

						Note that the newly queried domain can itself specify redirect
						processing.

					NOTE: Macros are not implemented
				*/
				if spf.Redirect != nil {
					return errors.New("Duplicate redirect modifier")
				}
				if modifier.Value == "" {
					return errors.New("No domain given for redirect modifier")
				}
				redirect_spf, err := NewSPF(modifier.Value, spf.dns)
				if err != nil {
					return err
				}
				spf.Redirect = redirect_spf

			}

		case "exp":
			{
				/*
					RFC 7208 6.2.
						If check_host() results in a "fail" due to a mechanism match (such as
						"-all"), and the "exp" modifier is present, then the explanation
						string returned is computed as described below.  If no "exp" modifier
						is present, then either a default explanation string or an empty
						explanation string MUST be returned to the calling application.

						The <domain-spec> is macro expanded (see Section 7) and becomes the
						<target-name>.  The DNS TXT RRset for the <target-name> is fetched.

						If there are any DNS processing errors (any RCODE other than 0), or
						if no records are returned, or if more than one record is returned,
						or if there are syntax errors in the explanation string, then proceed
						as if no "exp" modifier was given.
				*/

			}

		}

	}

	return nil
}

// GetRanges composes the CIDR IP ranges following RFC 4632 and RFC 4291
// of the given IPs, with a given IPv4 CIDR and IPv6 CIDR
func GetRanges(ips []string, ip4_cidr string, ip6_cidr string) ([]net.IPNet, error) {
	net_out := make([]net.IPNet, 0)

	for _, ip := range ips {
		cidr := ""
		if strings.Contains(ip, ":") {
			// IPv6
			cidr = ip6_cidr
			if cidr == "" {
				cidr = "128"
			}
			if c, err := strconv.ParseInt(cidr, 10, 16); err != nil || c < 0 || c > 128 {
				return nil, errors.New("Invalid IPv6 CIDR length: " + cidr)
			}

		} else {
			// IPv4
			cidr = ip4_cidr
			if cidr == "" {
				cidr = "32"
			}
			if c, err := strconv.ParseInt(cidr, 10, 16); err != nil || c < 0 || c > 32 {
				return nil, errors.New("Invalid IPv4 CIDR length: " + cidr)
			}
		}
		ip += "/" + cidr

		_, ipnet, err := net.ParseCIDR(ip)
		if err != nil {
			return nil, err
		}
		net_out = append(net_out, *ipnet)

	}

	return net_out, nil
}

/*
CheckIP checks if the given IP is a valid sender
(returns answers following section 2.6 from RFC 7208)

	result           = "Pass" / "Fail" / "SoftFail" / "Neutral" /
						"None" / "TempError" / "PermError"

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
func (spf *SPF) CheckIP(ip_str string) (string, error) {
	ip := net.ParseIP(ip_str)
	for _, ip_net := range spf.Fail {
		if ip_net.Contains(ip) {
			return "Fail", nil
		}
	}
	for _, ip_net := range spf.SoftFail {
		if ip_net.Contains(ip) {
			return "SoftFail", nil
		}
	}
	for _, ip_net := range spf.Neutral {
		if ip_net.Contains(ip) {
			return "Neutral", nil
		}
	}
	for _, ip_net := range spf.Pass {
		if ip_net.Contains(ip) {
			return "Pass", nil
		}
	}

	for _, include := range spf.Includes {
		/*
			RFC 7208 5.2
				The "include" mechanism triggers a recursive evaluation of
				check_host().

				1.  The <domain-spec> is expanded as per Section 7.

				2.  check_host() is evaluated with the resulting string as the
					<domain>.  The <ip> and <sender> arguments remain the same as in
					the current evaluation of check_host().

				3.  The recursive evaluation returns match, not-match, or an error.

				4.  If it returns match, then the appropriate result for the
					"include" mechanism is used (e.g., include or +include produces a
					"pass" result and -include produces "fail").

				5.  If it returns not-match or an error, the parent check_host()
					resumes processing as per the table below, with the previous
					value of <domain> restored.

				+---------------------------------+---------------------------------+
				| A recursive check_host() result | Causes the "include" mechanism  |
				| of:                             | to:                             |
				+---------------------------------+---------------------------------+
				| pass                            | match                           |
				|                                 |                                 |
				| fail                            | not match                       |
				|                                 |                                 |
				| softfail                        | not match                       |
				|                                 |                                 |
				| neutral                         | not match                       |
				|                                 |                                 |
				| temperror                       | return temperror                |
				|                                 |                                 |
				| permerror                       | return permerror                |
				|                                 |                                 |
				| none                            | return permerror                |
				+---------------------------------+---------------------------------+
		*/
		check, err := include.spf.CheckIP(ip_str)
		if err != nil {
			return "", nil
		}
		if check == "Pass" {
			return qualifierToResult(include.qualifier), nil
		}
	}

	// Check redirects
	/*
		RFC 7208 6.1.
			For clarity, any "redirect" modifier SHOULD appear as the very last
			term in a record.  Any "redirect" modifier MUST be ignored if there
			is an "all" mechanism anywhere in the record.
	*/
	if spf.All == "undefined" {
		if spf.Redirect != nil {
			return spf.Redirect.CheckIP(ip_str)
		}
	}

	// No results found -> check all
	if spf.All != "undefined" {
		return qualifierToResult(spf.All), nil
	}

	return "None", nil
}

func qualifierToResult(qualifier string) string {
	switch qualifier {
	case "+", "":
		return "Pass"
	case "?":
		return "Neutral"
	case "~":
		return "SoftFail"
	case "-":
		return "Fail"
	}
	return ""
}

func (spf SPF) toString(prefix string) string {

	out := prefix + "{\n"
	out += prefix + "  Domain:   " + spf.Domain + "\n"
	out += prefix + "  Pass:     " + fmt.Sprint(spf.Pass) + "\n"
	out += prefix + "  Neutral:  " + fmt.Sprint(spf.Neutral) + "\n"
	out += prefix + "  SoftFail: " + fmt.Sprint(spf.SoftFail) + "\n"
	out += prefix + "  Fail:     " + fmt.Sprint(spf.Fail) + "\n"
	out += prefix + "  All:      "
	out += func() string {
		switch spf.All {
		case "+":
			return "Pass"
		case "?":
			return "Neutral"
		case "~":
			return "SoftFail"
		case "-":
			return "Fail"
		default:
			return ""
		}
	}()
	out += "\n"
	out += prefix + "  Includes: "
	out += func() string {
		out := ""
		for _, i := range spf.Includes {
			out += i.qualifier
			out += i.spf.toString(prefix + "    ")
		}
		return out
	}()
	out += "\n"
	out += prefix + "  Redirect: "
	out += func() string {
		if spf.Redirect != nil {
			return spf.Redirect.toString(prefix + "    ")
		}
		return ""
	}()
	out += prefix + "\n"
	out += prefix + "}\n"
	return out

}
