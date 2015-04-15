GoSPF
=====

[![Build Status](https://travis-ci.org/gopistolet/gospf.svg?branch=master)](https://travis-ci.org/gopistolet/gospf)

*Sender Policy Framework for Go*

**Don't use, WIP**

Build
-----

Compile the code and run all unit tests:

    $ go build
    $ go test ./...


Run
---

You can run GoSPF in the console to validate an IP address against a domain: `./gospf domain ip ["debug"]`. e.g.:

    $ ./gospf google.com 66.249.80.0


With `debug` flag added, GoSPF will output the whole parsed SPF object.

Implementation
--------------

Will have support for directives and respective qualifiers, domain specs and IP(v4 and v6) addresses as defined in [RFC 7208](https://tools.ietf.org/html/rfc7208). `exists` mechanism isn't implemented yet. 
Support for `ptr` is no priority:

> Use of the ptr mechanism and the %p macro has been strongly
> discouraged (Sections 5.5 and 7.2).  The ptr mechanism and the %p
> macro remain part of the protocol because they were found to be in
> use, but records ought to be updated to avoid them.

I haven't started working on modifiers yet.