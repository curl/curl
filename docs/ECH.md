<!--
Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.

SPDX-License-Identifier: curl
-->

# Building curl with HTTPS-RR and ECH support

We have added support for ECH to curl. It can use HTTPS RRs published in the
DNS if curl uses DoH, or else can accept the relevant ECHConfigList values
from the command line. This works with OpenSSL, wolfSSL or BoringSSL as the
TLS provider.

This feature is EXPERIMENTAL. DO NOT USE IN PRODUCTION.

This should however provide enough of a proof-of-concept to prompt an informed
discussion about a good path forward for ECH support in curl.

## OpenSSL Build

To build our ECH-enabled OpenSSL fork:

```bash
    cd $HOME/code
    git clone https://github.com/defo-project/openssl
    cd openssl
    ./config --libdir=lib --prefix=$HOME/code/openssl-local-inst
    ...stuff...
    make -j8
    ...stuff (maybe go for coffee)...
    make install_sw
    ...a little bit of stuff...
```

To build curl ECH-enabled, making use of the above:

```bash
    cd $HOME/code
    git clone https://github.com/curl/curl
    cd curl
    autoreconf -fi
    LDFLAGS="-Wl,-rpath,$HOME/code/openssl-local-inst/lib/" ./configure --with-ssl=$HOME/code/openssl-local-inst --enable-ech --enable-httpsrr
    ...lots of output...
    WARNING: ECH HTTPSRR enabled but marked EXPERIMENTAL...
    make
    ...lots more output...
```

If you do not get that WARNING at the end of the ``configure`` command, then
ECH is not enabled, so go back some steps and re-do whatever needs re-doing:-)
If you want to debug curl then you should add ``--enable-debug`` to the
``configure`` command.

In a recent (2024-05-20) build on one machine, configure failed to find the
ECH-enabled SSL library, apparently due to the existence of
``$HOME/code/openssl-local-inst/lib/pkgconfig`` as a directory containing
various settings. Deleting that directory worked around the problem but may
not be the best solution.

## Using ECH and DoH

Curl supports using DoH for A/AAAA lookups so it was relatively easy to add
retrieval of HTTPS RRs in that situation. To use ECH and DoH together:

```bash
    cd $HOME/code/curl
    LD_LIBRARY_PATH=$HOME/code/openssl ./src/curl --ech true --doh-url https://one.one.one.one/dns-query https://defo.ie/ech-check.php
    ...
    SSL_ECH_STATUS: success <img src="greentick-small.png" alt="good" /> <br/>
    ...
```

The output snippet above is within the HTML for the webpage, when things work.

The above works for these test sites:

```bash
    https://defo.ie/ech-check.php
    https://draft-13.esni.defo.ie:8413/stats
    https://draft-13.esni.defo.ie:8414/stats
    https://crypto.cloudflare.com/cdn-cgi/trace
    https://tls-ech.dev
```

The list above has 4 different server technologies, implemented by 3 different
parties, and includes a case (the port 8414 server) where HelloRetryRequest
(HRR) is forced.

We currently support the following new curl command line arguments/options:

- ``--ech <config>`` - the ``config`` value can be one of:
    - ``false`` says to not attempt ECH
    - ``true`` says to attempt ECH, if possible
    - ``grease`` if attempting ECH is not possible, then send a GREASE ECH extension
    - ``hard`` hard-fail the connection if ECH cannot be attempted
    - ``ecl:<b64value>`` a base64 encoded ECHConfigList, rather than one accessed from the DNS
    - ``pn:<name>`` over-ride the ``public_name`` from an ECHConfigList

Note that in the above "attempt ECH" means the client emitting a TLS
ClientHello with a "real" ECH extension, but that does not mean that the
relevant server can succeed in decrypting, as things can fail for other
reasons.

## Supplying an ECHConfigList on the command line

To supply the ECHConfigList on the command line, you might need a bit of
cut-and-paste, e.g.:

```bash
    dig +short https defo.ie
    1 . ipv4hint=213.108.108.101 ech=AED+DQA8PAAgACD8WhlS7VwEt5bf3lekhHvXrQBGDrZh03n/LsNtAodbUAAEAAEAAQANY292ZXIuZGVmby5pZQAA ipv6hint=2a00:c6c0:0:116:5::10
```

Then paste the base64 encoded ECHConfigList onto the curl command line:

```bash
    LD_LIBRARY_PATH=$HOME/code/openssl ./src/curl --ech ecl:AED+DQA8PAAgACD8WhlS7VwEt5bf3lekhHvXrQBGDrZh03n/LsNtAodbUAAEAAEAAQANY292ZXIuZGVmby5pZQAA https://defo.ie/ech-check.php
    ...
    SSL_ECH_STATUS: success <img src="greentick-small.png" alt="good" /> <br/>
    ...
```

The output snippet above is within the HTML for the webpage.

If you paste in the wrong ECHConfigList (it changes hourly for ``defo.ie``) you
should get an error like this:

```bash
    LD_LIBRARY_PATH=$HOME/code/openssl ./src/curl -vvv --ech ecl:AED+DQA8yAAgACDRMQo+qYNsNRNj+vfuQfFIkrrUFmM4vogucxKj/4nzYgAEAAEAAQANY292ZXIuZGVmby5pZQAA https://defo.ie/ech-check.php
    ...
    * OpenSSL/3.3.0: error:0A00054B:SSL routines::ech required
    ...
```

There is a reason to want this command line option - for use before publishing
an ECHConfigList in the DNS as per the Internet-draft [A well-known URI for
publishing ECHConfigList values](https://datatracker.ietf.org/doc/draft-ietf-tls-wkech/).

If you do use a wrong ECHConfigList value, then the server might return a
good value, via the ``retry_configs`` mechanism. You can see that value in
the verbose output, e.g.:

```bash
    LD_LIBRARY_PATH=$HOME/code/openssl ./src/curl -vvv --ech ecl:AED+DQA8yAAgACDRMQo+qYNsNRNj+vfuQfFIkrrUFmM4vogucxKj/4nzYgAEAAEAAQANY292ZXIuZGVmby5pZQAA https://defo.ie/ech-check.php
    ...
* ECH: retry_configs AQD+DQA8DAAgACBvYqJy+Hgk33wh/ZLBzKSPgwxeop7gvojQzfASq7zeZQAEAAEAAQANY292ZXIuZGVmby5pZQAA/g0APEMAIAAgXkT5r4cYs8z19q5rdittyIX8gfQ3ENW4wj1fVoiJZBoABAABAAEADWNvdmVyLmRlZm8uaWUAAP4NADw2ACAAINXSE9EdXzEQIJZA7vpwCIQsWqsFohZARXChgPsnfI1kAAQAAQABAA1jb3Zlci5kZWZvLmllAAD+DQA8cQAgACASeiD5F+UoSnVoHvA2l1EifUVMFtbVZ76xwDqmMPraHQAEAAEAAQANY292ZXIuZGVmby5pZQAA
* ECH: retry_configs for defo.ie from cover.defo.ie, 319
    ...
```

At that point, you could copy the base64 encoded value above and try again.
For now, this only works for the OpenSSL and BoringSSL builds.

## Default settings

Curl has various ways to configure default settings, e.g. in ``$HOME/.curlrc``,
so one can set the DoH URL and enable ECH that way:

```bash
    cat ~/.curlrc
    doh-url=https://one.one.one.one/dns-query
    silent
    ech=true
```

Note that when you use the system's curl command (rather than our ECH-enabled
build), it is liable to warn that ``ech`` is an unknown option. If that is an
issue (e.g. if some script re-directs stdout and stderr somewhere) then adding
the ``silent`` line above seems to be a good enough fix. (Though of
course, yet another script could depend on non-silent behavior, so you may have
to figure out what you prefer yourself.) That seems to have changed with the
latest build, previously ``silent=TRUE`` was what I used in ``~/.curlrc`` but
now that seems to cause a problem, so that the following line(s) are ignored.

If you want to always use our OpenSSL build you can set ``LD_LIBRARY_PATH``
in the environment:

```bash
    export LD_LIBRARY_PATH=$HOME/code/openssl
```

When you do the above, there can be a mismatch between OpenSSL versions
for applications that check that. A ``git push`` for example fails so you
should unset ``LD_LIBRARY_PATH`` before doing that or use a different shell.

```bash
    git push
    OpenSSL version mismatch. Built against 30000080, you have 30200000
    ...
```

With all that setup as above the command line gets simpler:

```bash
    ./src/curl https://defo.ie/ech-check.php
    ...
    SSL_ECH_STATUS: success <img src="greentick-small.png" alt="good" /> <br/>
    ...
```

The ``--ech true`` option is opportunistic, so tries to do ECH but does not fail if
the client for example cannot find any ECHConfig values. The ``--ech hard``
option hard-fails if there is no ECHConfig found in DNS, so for now, that is not
a good option to set as a default. Once ECH has really been attempted by
the client, if decryption on the server side fails, then curl fails.

## Code changes for ECH support when using DoH

Code changes are ``#ifdef`` protected via ``USE_ECH`` or ``USE_HTTPSRR``:

- ``USE_HTTPSRR`` is used for HTTPS RR retrieval code that could be generically
  used should non-ECH uses for HTTPS RRs be identified, e.g. use of ALPN values
or IP address hints.

- ``USE_ECH`` protects ECH specific code.

There are various obvious code blocks for handling the new command line
arguments which are not described here, but should be fairly clear.

As shown in the ``configure`` usage above, there are ``configure.ac`` changes
that allow separately dis/enabling ``USE_HTTPSRR`` and ``USE_ECH``. If ``USE_ECH``
is enabled, then ``USE_HTTPSRR`` is forced. In both cases ``USE_DOH``
is required. (There may be some configuration conflicts available for the
determined:-)

The main functional change, as you would expect, is in ``lib/vtls/openssl.c``
where an ECHConfig, if available from command line or DNS cache, is fed into
the OpenSSL library via the new APIs implemented in our OpenSSL fork for that
purpose. This code also implements the opportunistic (``--ech true``) or hard-fail
(``--ech hard``) logic.

Other than that, the main additions are in ``lib/doh.c``
where we re-use ``dohprobe()`` to retrieve an HTTPS RR value for the target
domain. If such a value is found, that is stored using a new ``doh_store_https()``
function in a new field in the ``dohentry`` structure.

The qname for the DoH query is modified if the port number is not 443, as
defined in the SVCB specification.

When the DoH process has worked, ``Curl_doh_is_resolved()`` now also returns
the relevant HTTPS RR value data in the ``Curl_dns_entry`` structure.
That is later accessed when the TLS session is being established, if ECH is
enabled (from ``lib/vtls/openssl.c`` as described above).

## Limitations

Things that need fixing, but that can probably be ignored for the
moment:

- We could easily add code to make use of an ``alpn=`` value found in an HTTPS
  RR, passing that on to OpenSSL for use as the "inner" ALPN value, but have
yet to do that.

Current limitations (more interesting than the above):

- Only the first HTTPS RR value retrieved is actually processed as described
  above, that could be extended in future, though picking the "right" HTTPS RR
could be non-trivial if multiple RRs are published - matching IP address hints
versus A/AAAA values might be a good basis for that. Last I checked though,
browsers supporting ECH did not handle multiple HTTPS RRs well, though that
needs re-checking as it has been a while.

- It is unclear how one should handle any IP address hints found in an HTTPS RR.
  It may be that a bit of consideration of how "multi-CDN" deployments might
emerge would provide good answers there, but for now, it is not clear how best
curl might handle those values when present in the DNS.

- The SVCB/HTTPS RR specification supports a new "CNAME at apex" indirection
  ("aliasMode") - the current code takes no account of that at all. One could
envisage implementing the equivalent of following CNAMEs in such cases, but
it is not clear if that'd be a good plan. (As of now, chrome browsers do not seem
to have any support for that "aliasMode" and we have not checked Firefox for that
recently.)

- We have not investigated what related changes or additions might be needed
  for applications using libcurl, as opposed to use of curl as a command line
tool.

- We have not yet implemented tests as part of the usual curl test harness as
doing so would seem to require re-implementing an ECH-enabled server as part
of the curl test harness. For now, we have a ``./tests/ech_test.sh`` script
that attempts ECH with various test servers and with many combinations of the
allowed command line options. While that is a useful test and has find issues,
it is not comprehensive and we are not (as yet) sure what would be the right
level of coverage. When running that script you should not have a
``$HOME/.curlrc`` file that affects ECH or some of the negative tests could
produce spurious failures.

## Building with cmake

To build with cmake, assuming our ECH-enabled OpenSSL is as before:

```bash
    cd $HOME/code
    git clone https://github.com/curl/curl
    cd curl
    mkdir build
    cd build
    cmake -DOPENSSL_ROOT_DIR=$HOME/code/openssl -DUSE_ECH=1 -DUSE_HTTPSRR=1 ..
    ...
    make
    ...
    [100%] Built target curl
```

The binary produced by the cmake build does not need any ECH-specific
``LD_LIBRARY_PATH`` setting.

## BoringSSL build

BoringSSL is also supported by curl and also supports ECH, so to build
with that, instead of our ECH-enabled OpenSSL:

```bash
    cd $HOME/code
    git clone https://boringssl.googlesource.com/boringssl
    cd boringssl
    cmake -DCMAKE_INSTALL_PREFIX:PATH=$HOME/code/boringssl/inst -DBUILD_SHARED_LIBS=1
    make
    ...
    make install
```

Then:

```bash
    cd $HOME/code
    git clone https://github.com/curl/curl
    cd curl
    autoreconf -fi
    LDFLAGS="-Wl,-rpath,$HOME/code/boringssl/inst/lib" ./configure --with-ssl=$HOME/code/boringssl/inst --enable-ech --enable-httpsrr
    ...lots of output...
    WARNING: ECH HTTPSRR enabled but marked EXPERIMENTAL. Use with caution!
    make
```

The BoringSSL APIs are fairly similar to those in our ECH-enabled OpenSSL
fork, so code changes are also in ``lib/vtls/openssl.c``, protected
via ``#ifdef OPENSSL_IS_BORINGSSL`` and are mostly obvious API variations.

The BoringSSL APIs however do not support the ``--ech pn:`` command line
variant as of now.

## wolfSSL build

wolfSSL also supports ECH and can be used by curl, so here's how:

```bash
    cd $HOME/code
    git clone https://github.com/wolfSSL/wolfssl
    cd wolfssl
    ./autogen.sh
    ./configure --prefix=$HOME/code/wolfssl/inst --enable-ech --enable-debug --enable-opensslextra
    make
    make install
```

The install prefix (``inst``) in the above causes wolfSSL to be installed there
and we seem to need that for the curl configure command to work out. The
``--enable-opensslextra`` turns out (after much faffing about;-) to be
important or else we get build problems with curl below.

```bash
    cd $HOME/code
    git clone https://github.com/curl/curl
    cd curl
    autoreconf -fi
    ./configure --with-wolfssl=$HOME/code/wolfssl/inst --enable-ech --enable-httpsrr
    make
```

There are some known issues with the ECH implementation in wolfSSL:

- The main issue is that the client currently handles HelloRetryRequest
  incorrectly.  [HRR issue](https://github.com/wolfSSL/wolfssl/issues/6802).)
  The HRR issue means that the client does not work for
  [this ECH test web site](https://tls-ech.dev) and any other similarly configured
  sites.
- There is also an issue related to so-called middlebox compatibility mode.
  [middlebox compatibility issue](https://github.com/wolfSSL/wolfssl/issues/6774)

### Code changes to support wolfSSL

There are what seem like oddball differences:

- The DoH URL in``$HOME/.curlrc`` can use `1.1.1.1` for OpenSSL but has to be
  `one.one.one.one` for wolfSSL. The latter works for both, so OK, we us that.
- There seems to be some difference in CA databases too - the wolfSSL version
  does not like ``defo.ie``, whereas the system and OpenSSL ones do. We can
  ignore that for our purposes via ``--insecure``/``-k`` but would need to fix
  for a real setup. (Browsers do like those certificates though.)

Then there are some functional code changes:

- tweak to ``configure.ac`` to check if wolfSSL has ECH or not
- added code to ``lib/vtls/wolfssl.c`` mirroring what's done in the
  OpenSSL equivalent above.
- wolfSSL does not support ``--ech false`` or the ``--ech pn:`` command line
  argument.

The lack of support for ``--ech false`` is because wolfSSL has decided to
always at least GREASE if built to support ECH. In other words, GREASE is
a compile time choice for wolfSSL, but a runtime choice for OpenSSL or
BoringSSL. (Both are reasonable.)

## Additional notes

### Supporting ECH without DoH

All of the above only applies if DoH is being used. There should be a use-case
for ECH when DoH is not used by curl - if a system stub resolver supports DoT
or DoH, then, considering only ECH and the network threat model, it would make
sense for curl to support ECH without curl itself using DoH. The author for
example uses a combination of stubby+unbound as the system resolver listening
on localhost:53, so would fit this use-case. That said, it is unclear if
this is a niche that is worth trying to address. (The author is just as happy to
let curl use DoH to talk to the same public recursive that stubby might use:-)

Assuming for the moment this is a use-case we would like to support, then if
DoH is not being used by curl, it is not clear at this time how to provide
support for ECH. One option would seem to be to extend the ``c-ares`` library
to support HTTPS RRs, but in that case it is not now clear whether such
changes would be attractive to the ``c-ares`` maintainers, nor whether the
"tag=value" extensibility inherent in the HTTPS/SVCB specification is a good
match for the ``c-ares`` approach of defining structures specific to decoded
answers for each supported RRtype. We are also not sure how many downstream
curl deployments actually make use of the ``c-ares`` library, which would
affect the utility of such changes. Another option might be to consider using
some other generic DNS library that does support HTTPS RRs, but it is unclear
if such a library could or would be used by all or almost all curl builds and
downstream releases of curl.

Our current conclusion is that doing the above is likely best left until we
have some experience with the "using DoH" approach, so we are going to punt on
this for now.

### Debugging

Just a note to self as remembering this is a nuisance:

```bash
LD_LIBRARY_PATH=$HOME/code/openssl:./lib/.libs gdb ./src/.libs/curl
```

### Localhost testing

It can be useful to be able to run against a localhost OpenSSL ``s_server``
for testing. We have published instructions for such
[localhost tests](https://github.com/defo-project/ech-dev-utils/blob/main/howtos/localhost-tests.md)
in another repository. Once you have that set up, you can start a server
and then run curl against that:

```bash
    cd $HOME/code/ech-dev-utils
    ./scripts/echsvr.sh -d
    ...
```

The ``echsvr.sh`` script supports many ECH-related options. Use ``echsvr.sh -h``
for details.

In another window:

```bash
    cd $HOME/code/curl/
    ./src/curl -vvv --insecure  --connect-to foo.example.com:8443:localhost:8443  --ech ecl:AD7+DQA6uwAgACBix2B78sX+EQhEbxMspDOc8Z3xVS5aQpYP0Cxpc2AWPAAEAAEAAQALZXhhbXBsZS5jb20AAA==
```

### Automated use of ``retry_configs`` not supported so far...

As of now we have not added support for using ``retry_config`` handling in the
application - for a command line tool, one can just use ``dig`` (or ``kdig``)
to get the HTTPS RR and pass the ECHConfigList from that on the command line,
if needed, or one can access the value from command line output in verbose more
and then re-use that in another invocation.

Both our OpenSSL fork and BoringSSL have APIs for both controlling GREASE and
accessing and logging ``retry_configs``, it seems wolfSSL has neither.
