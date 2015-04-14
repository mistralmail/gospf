GoSPF
=====

[![Build Status](https://travis-ci.org/gopistolet/gospf.svg?branch=master)](https://travis-ci.org/gopistolet/gospf)

*Sender Policy Framework for Go*

**Don't use, WIP**


Implementation
--------------

Will have support for directives and respective qualifiers, domain specs and IP(v4 and v6) addresses as defined in [RFC 7208](https://tools.ietf.org/html/rfc7208).
Support for `ptr` is no priority:

> Use of the ptr mechanism and the %p macro has been strongly
> discouraged (Sections 5.5 and 7.2).  The ptr mechanism and the %p
> macro remain part of the protocol because they were found to be in
> use, but records ought to be updated to avoid them.

Haven't start working on modifiers yet.