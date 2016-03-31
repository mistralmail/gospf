GoSPF
=====

[![Build Status](https://travis-ci.org/gopistolet/gospf.svg?branch=master)](https://travis-ci.org/gopistolet/gospf)

*Sender Policy Framework for Go*


Usage
-----

Get GoSPF and run all unit test:

    $ go get github.com/gopistolet/gospf
    $ cd $GOPATH/src/github.com/gopistolet/gospf
    $ go test ./...

### Command line tool

Compile the code:

    $ go build -o spf github.com/gopistolet/gospf/gospf

You can run GoSPF in the console to validate an IP address against a domain: `./spf domain ip ["debug"]`. e.g.:

    $ ./spf google.com 66.249.80.0

*With `debug` flag added, GoSPF will output the whole parsed SPF object.*


### Library

GoSPF is meant to be included in other projects.
To use GoSPF you must create a new `SPF` instance (witch takes a domain and a `gospf/dns` interface).
Once you have the `SPF` instance you can call `CheckIP(ip string)` on it,
which will return a response following [*RFC 7208 2.6. Results of Evaluation*](https://tools.ietf.org/html/rfc7208#section-2.6)
(i.e. `Neutral`, `Pass`, `SoftFail`, `Fail`, ...)

Example:

```go
package main

import (
    "fmt"
    "github.com/gopistolet/gospf"
    "github.com/gopistolet/gospf/dns"
)

func main() {

    domain := "google.com"
    ip     := "66.249.80.0"

    // create SPF instance
    spf, err := gospf.New(domain, &dns.GoSPFDNS{})
    if err != nil {
        fmt.Println(err)
        return
    }

    // check the given IP on that instance
    check, err := spf.CheckIP(ip)
    if err != nil {
        fmt.Println(err)
        return
    }

    fmt.Println(ip, "->", check)

}

```


Implementation
--------------

**Directives**  
GoSPF supports `all`, `include`, `a`, `mx`, `ip4` and `ip6` mechanisms with the respective qualifiers `+`, `?`, `~` and `-`. All implemented as defined in [RFC 7208](https://tools.ietf.org/html/rfc7208).
Support for `exists` mechanism isn't implemented yet. 
Support for `ptr` mechanism is no priority:

> Use of the ptr mechanism and the %p macro has been strongly
> discouraged (Sections 5.5 and 7.2).  The ptr mechanism and the %p
> macro remain part of the protocol because they were found to be in
> use, but records ought to be updated to avoid them.

**Modifiers**  
Currently only support for `redirect` modifier. (Other modifiers won't cause parse errors.)

**Macros**  
Macros aren't supported (yet).


License
-------

GoSPF is licensed under the [BSD 2-clause “Simplified” License](https://github.com/gopistolet/gospf/blob/master/LICENSE.txt).


Author
------

Mathias Beke - [denbeke.be]()
