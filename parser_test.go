package gospf

import (
	_ "fmt"
	. "github.com/smartystreets/goconvey/convey"
	"testing"
)

func TestGetTerms(t *testing.T) {

	Convey("Testing getTerms()", t, func() {

		records := []struct {
			record     string
			directives []Directive
			modifiers  []Modifier
		}{
			{
				record:     "v=spf1 a -all",
				directives: []Directive{Directive{term: "a"}, Directive{term: "-all"}},
				modifiers:  []Modifier{},
			},
			{
				record:     "v=spf1 a:mail.example.com ~all",
				directives: []Directive{Directive{term: "a:mail.example.com"}, Directive{term: "~all"}},
				modifiers:  []Modifier{},
			},
			{
				record: "v=spf1 ip4:192.0.2.0/24 ip4:198.51.100.123 a -all",
				directives: []Directive{
					Directive{term: "ip4:192.0.2.0/24"},
					Directive{term: "ip4:198.51.100.123"},
					Directive{term: "a"},
					Directive{term: "-all"},
				},
				modifiers: []Modifier{},
			},
		}

		for _, record := range records {
			directives, modifiers, err := getTerms(record.record)
			So(err, ShouldEqual, nil)
			So(directives, ShouldResemble, record.directives)
			So(modifiers, ShouldResemble, record.modifiers)
		}

	})

}

func TestDirective(t *testing.T) {

	Convey("Testing Directive.getQualifier()", t, func() {

		terms := []struct {
			d Directive
			q string
		}{
			{
				d: Directive{term: "ip4:192.0.2.0/24"},
				q: "",
			},
			{
				d: Directive{term: "-a"},
				q: "-",
			},
			{
				d: Directive{term: "+mx:mail.example.com"},
				q: "+",
			},
			{
				d: Directive{term: "~all"},
				q: "~",
			},
			{
				d: Directive{term: "?include:_spf.google.com"},
				q: "?",
			},
		}

		for _, term := range terms {
			So(term.d.getQualifier(), ShouldEqual, term.q)
		}

	})

	Convey("Testing Directive.getMechanism()", t, func() {

		terms := []struct {
			d Directive
			m string
		}{
			{
				d: Directive{term: "ip4:192.0.2.0/24"},
				m: "ip4",
			},
			{
				d: Directive{term: "-a"},
				m: "a",
			},
			{
				d: Directive{term: "a"},
				m: "a",
			},
			{
				d: Directive{term: "mx:mail.example.com"},
				m: "mx",
			},
			{
				d: Directive{term: "~all"},
				m: "all",
			},
			{
				d: Directive{term: "exists:example.com"},
				m: "exists",
			},
			{
				d: Directive{term: "include:_spf.google.com"},
				m: "include",
			},
		}

		for _, term := range terms {
			So(term.d.getMechanism(), ShouldEqual, term.m)
		}

	})

	Convey("Testing Directive.getArguments()", t, func() {

		terms := []struct {
			d    Directive
			args map[string]string
		}{
			{
				d:    Directive{term: "ip4:192.0.2.0/24"},
				args: map[string]string{"ip": "192.0.2.0", "ip4-cidr": "24"},
			},
			{
				d:    Directive{term: "ip6:1080::8:800:68.0.3.1/96"},
				args: map[string]string{"ip": "1080::8:800:68.0.3.1", "ip6-cidr": "96"},
			},
			{
				d:    Directive{term: "a/32"},
				args: map[string]string{"ip4-cidr": "32", "ip6-cidr": ""},
			},
			{
				d:    Directive{term: "a/24//96"},
				args: map[string]string{"ip4-cidr": "24", "ip6-cidr": "96"},
			},
			{
				d:    Directive{term: "mx:foo.com//126"},
				args: map[string]string{"domain": "foo.com", "ip4-cidr": "", "ip6-cidr": "126"},
			},
			{
				d:    Directive{term: "mx:foo.com/32"},
				args: map[string]string{"domain": "foo.com", "ip4-cidr": "32", "ip6-cidr": ""},
			},
			{
				d:    Directive{term: "mx:foo.com"},
				args: map[string]string{"domain": "foo.com", "ip4-cidr": "", "ip6-cidr": ""},
			},
		}

		for _, term := range terms {
			So(term.d.getArguments(), ShouldResemble, term.args)
		}

	})

}

func TestModifiers(t *testing.T) {

	Convey("Testing Modifiers.process()", t, func() {

		modifiers := []struct {
			m Modifiers
			k string
			v string
		}{
			{
				m: Modifiers{Modifier{term: "redirect=_spf.example.com"}},
				k: "redirect",
				v: "_spf.example.com",
			},
			{
				m: Modifiers{Modifier{term: "redirect="}},
				k: "redirect",
				v: "",
			},
			{
				m: Modifiers{Modifier{term: "exp=explain._spf.%{d}"}},
				k: "exp",
				v: "explain._spf.%{d}",
			},
		}

		for _, modifier := range modifiers {
			modifier.m.process()
			So(modifier.m[0].Key, ShouldEqual, modifier.k)
			So(modifier.m[0].Value, ShouldEqual, modifier.v)
		}

	})

}
