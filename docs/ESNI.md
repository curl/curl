# TLS: ESNI support in curl and libcurl

## Summary

**ESNI** means **Encrypted Server Name Indication**, a TLS 1.3
extension which is currently the subject of an
[IETF Draft][tlsesni].

This file is intended to show the current state of ESNI support in
**curl** and **libcurl**.

An [experimental fork of curl][niallorcurl], when built using an
ESNI-capable TLS backend (such as this [experimental fork of
OpenSSL][sftcdopenssl]), provides a proof of concept for ESNI support,
and has been demonstrated interoperating with a server belonging to
the [DEfO Project][defoproj].

Further sections here describe

-   TODO items,

-   progress to date,

-   resources needed for building and demonstrating **curl** support
    for ESNI, including instructions, and

-   additional details of specific stages of the progress.

## TODO

-   Identify architecturally correct per-connection or per-host
    propagation path for ESNI data fetched from DNS.

-   (WIP) Work with OpenSSL community to finalize ESNI API.

-   (WIP) Track OpenSSL ESNI API in libcurl

-   (WIP) Track progress on IETF ESNI draft

-   Identify and implement any changes needed for CMake.

-   Optimize existing build-time checking of available resources.

-   Encourage ESNI support work on other TLS backends.

-   Explore how c-ares might be used instead of DOH for retrieving
    ESNI parameters from DNS.

-   Extend build-time checking of available resources to
    accommodate other TLS backends as these become available.

## Progress

### ESNI-demo (PR 4468, Oct 2019 onwards)

-   Add libcurl options to set ESNI parameters.

-   Add support code to propagate parameters to TLS backend

-   Add curl tool command-line options to set ESNI parameters.

-   (Jan 2020) Remove certain libcurl and command-line options
    identified as unnecessary.

-   (Jan 2020) Extend DoH functions so that published ESNI parameters
    can be retrieved from DNS instead of being required as options.

### PR 4011 (Jun 2019) included in curl release 7.67.0 (Oct 2019)

-   Details [below](#pr4011);

-   New **curl** feature: `CURL_VERSION_ESNI`;

-   New configuration option: `--enable-esni`;

-   Build-time check for availability of resources needed for ESNI
    support;

-   Pre-processor symbol `USE_ESNI` for conditional compilation of
    ESNI support code, subject to configuration option and
    availability of needed resources.

## Resources needed

To build and demonstrate ESNI support in **curl** and/or **libcurl**,
you will need

-   a TLS library, supported by **libcurl**, which implements ESNI;

-   an edition of **curl** and/or **libcurl** which supports the ESNI
    implementation of the chosen TLS library;

-   an environment for building and running **curl**, and at least
    building **OpenSSL**;

-   a target URL, hosted on a server supporting ESNI, against which 
    to run a demonstration;

-   a server, running DOH, from which to retrieve ESNI parameters
    for the target URL; and

-   some instructions.

The following set of resources is currently known to be available.

| Set  | Component       | Location                          | Remarks                           |
|:-----|:----------------|:----------------------------------|:----------------------------------|
| DEfO | TLS library     | [sftcd/openssl][sftcdopenssl]     | Development repository            |
|      |                 | [niallor/openssl][nialloropenssl] | Tag *demo* lags development so as |
|      |                 |                                   | to avoid "bleeding edge" effect   |
|      | curl fork       | [niallor/curl][niallorcurl]       | Branch *ESNI-demo*                |
| curl | DOH server list | [curl wiki][curlwikidoh]          |                                   |
|      | instructions    | here below                        |                                   |

### Instructions for building curl with ESNI support

First take a look at the files *docs/INSTALL.md* and GIT-INFO,
and ensure that the packages mentioned in the latter are available.

The sequence of commands shown below is an example of how a curl
executable with ESNI support might be built and demonstrated on a
Linux system.

```
# Set up and populate a work area
cd `mktemp -d`
WORK=$PWD
mkdir installed
git clone --branch demo https://github.com/niallor/openssl
git clone --branch ESNI-demo https://github.com/niallor/curl

# Build OpenSSL
cd $WORK/openssl
./config --prefix=$WORK/installed
make

# Optionally run the OpenSSL test suite
make test

# Make OpenSSL components available for building curl
make install_sw

# Build curl
cd $WORK/curl
./buildconf
./configure \
    --disable-shared \
    --enable-debug \
    --enable-maintainer-mode \
    --with-ssl=$WORK/installed \
    --enable-esni
make

# Set up run-time environment
export LD_LIBRARY_PATH=$WORK/installed/lib

# Optionally run the curl test suite
make test

# Demonstrate curl support of ESNI, using ESNI parameters
# retrieved using DOH from some one of the DOH servers listed
# at https://github.com/curl/curl/wiki/DNS-over-HTTPS

# For example:
$DOH_URL=https://doh.powerdns.org/

src/curl \
    --verbose \
    --doh-url $DOH_URL \
    --esni \
    --head \
    https://encryptedsni.com/
```

## Additional detail

### ESNI-demo (PR 4468)

**TLS: Provide demonstration ESNI implementation for curl and libcurl**

-   Define libcurl options for ESNI

    -   New options with associated man pages:

        -   `CURLOPT_ESNI_ASCIIRR`
        -   `CURLOPT_ESNI_COVER`
        -   `CURLOPT_ESNI_STATUS`

-   Implement libcurl support for ESNI

    -   ESNI key data, fetched using DoH or specified as an option, is
        propagated to an ESNI-capable TLS backend.

-   Implement curl tool support for ESNI

    -   New command-line options with associated man pages:

        -   `--esni`\
            (boolean: off if first ESNI option is `--no-esni`)

        -   `--esni-cover=HOSTNAME` (cover name to send as SNI)

        -   `--esni-load=ESNIKEYS` (Base64 or hex literal, or file)

-   Update this documentation file, *docs/ESNI.md*

-   Limitations not covered by TODO list:

    -   A per-host or per-connection propagation path for ESNI
        parameter data fetched using DoH needs to be identified for
        use instead of overloading the CURLOPT\_ESNI\_ASCIIRR string
        in the easy handle.

    -   Book-keeping for new options needs real release number
        instead of `DUMMY`.

### PR 4011

**TLS: Provide ESNI support framework for curl and libcurl**

The proposed change provides a framework to facilitate work to
implement ESNI support in curl and libcurl. It is not intended
either to provide ESNI functionality or to favour any particular
TLS-providing backend. Specifically, the change reserves a
feature bit for ESNI support (symbol `CURL_VERSION_ESNI`),
implements setting and reporting of this bit, includes dummy
book-keeping for the symbol, adds a build-time configuration
option (`--enable-esni`), provides an extensible check for
resources available to provide ESNI support, and defines a
compiler pre-processor symbol (`USE_ESNI`) accordingly.

Proposed-by: @niallor (Niall O'Reilly)\
Encouraged-by: @sftcd (Stephen Farrell)\
See-also: [this message](https://curl.haxx.se/mail/lib-2019-05/0108.html)

Limitations:
-   Book-keeping (symbols-in-versions) needs real release number, not 'DUMMY'.

-   Framework is incomplete, as it covers autoconf, but not CMake.

-   Check for available resources, although extensible, refers only to
    specific work in progress ([described
    here](https://github.com/sftcd/openssl/tree/master/esnistuff)) to
    implement ESNI for OpenSSL, as this is the immediate motivation
    for the proposed change.

## References

Cloudflare blog: [Encrypting SNI: Fixing One of the Core Internet Bugs][corebug]

Cloudflare blog: [Encrypt it or lose it: how encrypted SNI works][esniworks]

IETF Draft: [Encrypted Server Name Indication for TLS 1.3][tlsesni]

---



[tlsesni]:		  https://datatracker.ietf.org/doc/draft-ietf-tls-esni/
[esniworks]:	  https://blog.cloudflare.com/encrypted-sni/
[corebug]:		  https://blog.cloudflare.com/esni/
[defoproj]:		  https://defo.ie/
[sftcdopenssl]:   https://github.com/sftcd/openssl/
[nialloropenssl]: https://github.com/niallor/openssl/
[niallorcurl]:	  https://github.com/niallor/curl/
[curlwikidoh]:    https://github.com/curl/curl/wiki/DNS-over-HTTPS
