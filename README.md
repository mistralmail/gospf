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

GoSPF is licensed under the BSD 2-clause “Simplified” License:

> Copyright (c) 2015, Mathias Beke
> All rights reserved.
> 
> Redistribution and use in source and binary forms, with or without
> modification, are permitted provided that the following conditions are met:
> 
> * Redistributions of source code must retain the above copyright notice, this
>   list of conditions and the following disclaimer.
> 
> * Redistributions in binary form must reproduce the above copyright notice,
>   this list of conditions and the following disclaimer in the documentation
>   and/or other materials provided with the distribution.
> 
> THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
> AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
> IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
> DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
> FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
> DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
> SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
> CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
> OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
> OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.


Author
------

Mathias Beke - [denbeke.be](http://denbeke.be)
