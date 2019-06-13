# TLS: Provide ESNI support framework for curl and libcurl

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

Proposed-by: @niallor (Niall O'Reilly)
Encouraged-by: @sftcd (Stephen Farrell)
See-also: [this message](https://curl.haxx.se/mail/lib-2019-05/0108.html)
Limitations:
-   Book-keeping (symbols-in-versions) needs real release number, not 'DUMMY'.

-   Framework is incomplete, as it covers autoconf, but not cmake.

-   Check for available resources, although extensible, refers only to
    specific work in progress ([described
    here](https://github.com/sftcd/openssl/tree/master/esnistuff)) to
    implement ESNI for OpenSSL, as this is the immediate motivation
    for the proposed change.
