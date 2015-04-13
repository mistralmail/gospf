package main

import (
	_ "fmt"
	. "github.com/smartystreets/goconvey/convey"
	"testing"
)

func TestGetTerms(t *testing.T) {

	Convey("Testing getTerms()", t, func() {

		records := []struct {
			record     string
			directives []directive
			modifiers  []modifier
		}{
			{
				record:     "v=spf1 a -all",
				directives: []directive{directive{term: "a"}, directive{term: "-all"}},
				modifiers:  []modifier{},
			},
			{
				record:     "v=spf1 a:mail.example.com ~all",
				directives: []directive{directive{term: "a:mail.example.com"}, directive{term: "~all"}},
				modifiers:  []modifier{},
			},
			{
				record: "v=spf1 ip4:192.0.2.0/24 ip4:198.51.100.123 a -all",
				directives: []directive{
					directive{term: "ip4:192.0.2.0/24"},
					directive{term: "ip4:198.51.100.123"},
					directive{term: "a"},
					directive{term: "-all"},
				},
				modifiers: []modifier{},
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

	Convey("Testing directive.getQualifier()", t, func() {

		terms := []struct {
			d directive
			q string
		}{
			{
				d: directive{term: "ip4:192.0.2.0/24"},
				q: "",
			},
			{
				d: directive{term: "-a"},
				q: "-",
			},
			{
				d: directive{term: "+mx:mail.example.com"},
				q: "+",
			},
			{
				d: directive{term: "~all"},
				q: "~",
			},
			{
				d: directive{term: "?include:_spf.google.com"},
				q: "?",
			},
		}

		for _, term := range terms {
			So(term.d.getQualifier(), ShouldEqual, term.q)
		}

	})

	Convey("Testing directive.getMechanism()", t, func() {

		terms := []struct {
			d directive
			m string
		}{
			{
				d: directive{term: "ip4:192.0.2.0/24"},
				m: "ip4",
			},
			{
				d: directive{term: "-a"},
				m: "a",
			},
			{
				d: directive{term: "mx:mail.example.com"},
				m: "mx",
			},
			{
				d: directive{term: "~all"},
				m: "all",
			},
			{
				d: directive{term: "exists:example.com"},
				m: "exists",
			},
			{
				d: directive{term: "include:_spf.google.com"},
				m: "include",
			},
		}

		for _, term := range terms {
			So(term.d.getMechanism(), ShouldEqual, term.m)
		}

	})

}
