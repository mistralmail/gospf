package main

import (
	"errors"
	"strings"
)

/*
RFC 4408: (grammar for SPF record)

	This section is normative and any discrepancies with the ABNF
	fragments in the preceding text are to be resolved in favor of this
	grammar.

	See [RFC4234] for ABNF notation.  Please note that as per this ABNF
	definition, literal text strings (those in quotes) are case-
	insensitive.  Hence, "mx" matches "mx", "MX", "mX", and "Mx".

	record           = version terms *SP
	version          = "v=spf1"

	terms            = *( 1*SP ( directive / modifier ) )

	directive        = [ qualifier ] mechanism
	qualifier        = "+" / "-" / "?" / "~"
	mechanism        = ( all / include
					   / A / MX / PTR / IP4 / IP6 / exists )

	all              = "all"
	include          = "include"  ":" domain-spec
	A                = "a"      [ ":" domain-spec ] [ dual-cidr-length ]
	MX               = "mx"     [ ":" domain-spec ] [ dual-cidr-length ]
	PTR              = "ptr"    [ ":" domain-spec ]
	IP4              = "ip4"      ":" ip4-network   [ ip4-cidr-length ]
	IP6              = "ip6"      ":" ip6-network   [ ip6-cidr-length ]
	exists           = "exists"   ":" domain-spec

	modifier         = redirect / explanation / unknown-modifier
	redirect         = "redirect" "=" domain-spec
	explanation      = "exp" "=" domain-spec
	unknown-modifier = name "=" macro-string

	ip4-cidr-length  = "/" 1*DIGIT
	ip6-cidr-length  = "/" 1*DIGIT
	dual-cidr-length = [ ip4-cidr-length ] [ "/" ip6-cidr-length ]

	ip4-network      = qnum "." qnum "." qnum "." qnum
	qnum             = DIGIT                 ; 0-9
					   / %x31-39 DIGIT       ; 10-99
					   / "1" 2DIGIT          ; 100-199
					   / "2" %x30-34 DIGIT   ; 200-249
					   / "25" %x30-35        ; 250-255
			  ; conventional dotted quad notation.  e.g., 192.0.2.0
	ip6-network      = <as per [RFC 3513], section 2.2>
			  ; e.g., 2001:DB8::CD30

	domain-spec      = macro-string domain-end
	domain-end       = ( "." toplabel [ "." ] ) / macro-expand
	toplabel         = ( *alphanum ALPHA *alphanum ) /
					   ( 1*alphanum "-" *( alphanum / "-" ) alphanum )
					   ; LDH rule plus additional TLD restrictions
					   ; (see [RFC3696], Section 2)

	alphanum         = ALPHA / DIGIT

	explain-string   = *( macro-string / SP )

	macro-string     = *( macro-expand / macro-literal )
	macro-expand     = ( "%{" macro-letter transformers *delimiter "}" )
					   / "%%" / "%_" / "%-"
	macro-literal    = %x21-24 / %x26-7E
					   ; visible characters except "%"
	macro-letter     = "s" / "l" / "o" / "d" / "i" / "p" / "h" /
					   "c" / "r" / "t"
	transformers     = *DIGIT [ "r" ]
	delimiter        = "." / "-" / "+" / "," / "/" / "_" / "="

	name             = ALPHA *( ALPHA / DIGIT / "-" / "_" / "." )

	header-field     = "Received-SPF:" [CFWS] result FWS [comment FWS]
					   [ key-value-list ] CRLF

	result           = "Pass" / "Fail" / "SoftFail" / "Neutral" /
					   "None" / "TempError" / "PermError"

	key-value-list   = key-value-pair *( ";" [CFWS] key-value-pair )
					   [";"]

	key-value-pair   = key [CFWS] "=" ( dot-atom / quoted-string )

	key              = "client-ip" / "envelope-from" / "helo" /
					   "problem" / "receiver" / "identity" /
						mechanism / "x-" name / name

	identity         = "mailfrom"   ; for the "MAIL FROM" identity
					   / "helo"     ; for the "HELO" identity
					   / name       ; other identities

	dot-atom         = <unquoted word as per [RFC2822]>
	quoted-string    = <quoted string as per [RFC2822]>
	comment          = <comment string as per [RFC2822]>
	CFWS             = <comment or folding white space as per [RFC2822]>
	FWS              = <folding white space as per [RFC2822]>
	CRLF             = <standard end-of-line token as per [RFC2822]>
*/

/*
	directive        = [ qualifier ] mechanism
	qualifier        = "+" / "-" / "?" / "~"
	mechanism        = ( all / include
					   / A / MX / PTR / IP4 / IP6 / exists )

	all              = "all"
	include          = "include"  ":" domain-spec
	A                = "a"      [ ":" domain-spec ] [ dual-cidr-length ]
	MX               = "mx"     [ ":" domain-spec ] [ dual-cidr-length ]
	PTR              = "ptr"    [ ":" domain-spec ]
	IP4              = "ip4"      ":" ip4-network   [ ip4-cidr-length ]
	IP6              = "ip6"      ":" ip6-network   [ ip6-cidr-length ]
	exists           = "exists"   ":" domain-spec
*/
type directive struct {
	term string
}

func isQualifier(char uint8) bool {
	qualifiers := []uint8{
		'+',
		'-',
		'?',
		'~',
	}

	for _, q := range qualifiers {
		if q == char {
			return true
		}
	}

	return false
}

func (d *directive) getQualifier() string {
	if isQualifier(d.term[0]) {
		return string(d.term[0])
	} else {
		return ""
	}
}

func (d *directive) getMechanism() string {
	term := d.term
	if isQualifier(d.term[0]) {
		term = term[1:len(term)]
	}
	index := strings.Index(term, ":")
	if index == -1 {
		return term
	}
	return term[0:index]
}

/*
	modifier         = redirect / explanation / unknown-modifier
	redirect         = "redirect" "=" domain-spec
	explanation      = "exp" "=" domain-spec
	unknown-modifier = name "=" macro-string
*/
type modifier struct {
	term string
}

func isModifier(term string) bool {
	if strings.Index(term, "=") != -1 {
		return true
	} else {
		return false
	}
}

func getTerms(record string) ([]directive, []modifier, error) {
	version := "v=spf1"
	terms := strings.Split(record, " ")

	if terms[0] != version {
		return nil, nil, errors.New("Unsupported SPF version: " + terms[0])
	}

	directives := make([]directive, 0)
	modifiers := make([]modifier, 0)

	for _, term := range terms[1:len(terms)] {
		if isModifier(term) {
			modifiers = append(modifiers, modifier{term: term})
		} else {
			directives = append(directives, directive{term: term})
		}
	}

	return directives, modifiers, nil
}
