## curl and libcurl 7.82.0
---
 Public curl releases:         206  
 Command line options:         245  
 curl_easy_setopt() options:   295  
 Public functions in libcurl:  86  
 Contributors:                 2588  

---
This release includes the following changes:

 - curl: add --json [67]
 - mesalink: remove support [23]

This release includes the following bugfixes:

 - appveyor: update images from VS 2019 to 2022
 - appveyor: use VS 2017 image for the autotools builds
 - build: enable -Warith-conversion
 - build: fix -Wenum-conversion handling
 - build: fix ngtcp2 crypto library detection [63]
 - checksrc: fix typo in comment [34]
 - CI: move 'distcheck' job from zuul to azure pipelines [60]
 - CI: move scan-build job from Zuul to Azure Pipelines [59]
 - CI: move the NSS job from zuul to GHA [84]
 - ci: move the OpenSSL + c-ares job from Zuul to Circle CI [75]
 - CI: move the rustls CI job to GHA from Zuul [8]
 - CI: move two jobs from Zuul to Circle CI [73]
 - CI: test building wolfssl with --enable-opensslextra [42]
 - CI: workflows/wolfssl: install impacket [47]
 - circleci: add a job using libssh [121]
 - cirlceci: also run a c-ares job on arm with debug enabled [74]
 - cmake: fix iOS CMake project generation error [13]
 - cmdline-opts/gen.pl: fix option matching to improve references [50]
 - config.d: Clarify _curlrc filename is still valid on Windows [95]
 - configure: fix '--enable-code-coverage' typo [110]
 - configure: remove support for "embedded ares" [82]
 - configure: requires --with-nss-deprecated to build with NSS [114]
 - configure: set CURL_LIBRARY_PATH for nghttp2 [58]
 - configure: support specification of a nghttp2 library path [101]
 - configure: use correct CFLAGS for threaded resolver with xlC on AIX [54]
 - curl tool: erase some more sensitive command line arguments [22]
 - curl-functions.m4: fix LIBRARY_PATH adjustment to avoid eval [5]
 - curl-functions.m4: revert DYLD_LIBRARY_PATH tricks in CURL_RUN_IFELSE [9]
 - curl-openssl: fix SRP check for OpenSSL 3.0 [86]
 - curl-openssl: remove the OpenSSL headers and library versions check [35]
 - curl: remove "separators" (when using globbed URLs) [32]
 - curl_getdate.3: remove pointless .PP line [68]
 - curl_multi_socket.3: remove callback and typical usage descriptions [7]
 - curl_url_set.3: mention when CURLU_ALLOW_SPACE was added
 - CURLMOPT_TIMERFUNCTION/DATA.3: fix the examples [27]
 - CURLOPT_RESOLVE.3: change example port to 443
 - CURLSHOPT_LOCKFUNC.3: fix typo "relased" -> "released" [71]
 - docs/cmdline-opts: add "mutexed" options for more http versions [25]
 - docs/DEPRECATE: remove NPN support in August 2022 [64]
 - docs: capitalize the name 'Netscape' [77]
 - docs: document HTTP/2 not insisting on TLS 1.2 [49]
 - docs: fix mandoc -T lint formatting complaints [2]
 - docs: update IETF links to use datatracker [41]
 - examples/multi-app.c: call curl_multi_remove_handle as well [19]
 - formdata: avoid size_t => long typecast overflows [37]
 - ftp: provide error message for control bytes in path [66]
 - gen.pl: terminate "example" sections better [4]
 - gskit: Convert to using Curl_poll [111]
 - gskit: Fix errors from Curl_strerror refactor [113]
 - gskit: Fix initialization of Curl_ssl_gskit struct [112]
 - h2/h3: allow CURLOPT_HTTPHEADER change ":scheme" [88]
 - hostcheck: fixed to not touch used input strings [38]
 - hostcheck: reduce strlen calls on chained certificates [92]
 - http: make Curl_compareheader() take string length arguments too [87]
 - if2ip: make Curl_ipv6_scope a blank macro when IPv6-disabled [104]
 - KNOWN_BUGS: fix typo "libpsl"
 - ldap: return CURLE_URL_MALFORMAT for bad URL [24]
 - lib: remove support for CURL_DOES_CONVERSIONS [96]
 - Makefile.am: Generate VS 2022 projects
 - maketgz: return error if 'make dist' fails [79]
 - mbedtls: enable use of mbedtls without CRL support [57]
 - mbedtls: enable use of mbedtls without filesystem functions support [100]
 - mbedtls: fix CURLOPT_SSLCERT_BLOB (again)
-o mbedtls: fix ssl_init error with mbedTLS 3.1.0+ [12]
 - mbedtls: remove #include <mbedtls/certs.h> [56]
 - mbedtls: return CURLcode result instead of a mbedtls error code [1]
 - md5: check md5_init_func return value
 - mime: use a define instead of the magic number 24 [89]
 - misc: allow curl to build with wolfssl --enable-opensslextra [43]
 - misc: remove BeOS code and references [30]
 - misc: remove the final watcom references [29]
 - misc: remove unused data when IPv6 is not supported [80]
 - mqtt: free 'sendleftovers' in disconnect [115]
 - mqtt: free any send leftover data when done [36]
 - multi: grammar fix in comment [69]
 - multi: remember connection_id before returning connection to pool [76]
 - multi: set in_callback for multi interface callbacks [28]
 - netware: remove support [72]
 - next.d. remove .fi/.nf as they are handled by gen.pl [3]
 - ngtcp2: adapt to changed end of headers callback proto [39]
 - ngtcp2: fix declaration of ‘result’ shadows a previous local [14]
 - nss: handshake callback during shutdown has no conn->bundle [55]
 - ntlm: remove unused feature defines [117]
 - openldap: fix compiler warning when built without SSL support [70]
 - openldap: implement SASL authentication [16]
 - openldap: pass string length arguments to client_write() [116]
 - openssl.h: avoid including OpenSSL headers here [15]
 - openssl: check SSL_get_ex_data to prevent potential NULL dereference [40]
 - openssl: check the return value of BIO_new_mem_buf() [18]
 - openssl: fix `ctx_option_t` for OpenSSL v3+
 - openssl: return error if TLS 1.3 is requested when not supported [45]
 - projects: add support for Visual Studio 17 (2022) [124]
 - projects: fix Visual Studio wolfSSL configurations
 - projects: remove support for MSVC before VC10 (Visual Studio 2010) [123]
 - quiche: after leaving h3_recving state, poll again [108]
 - quiche: change qlog file extension to `.sqlog` [44]
 - quiche: handle stream reset [83]
 - quiche: verify the server cert on connect [33]
 - quiche: when *recv_body() returns data, drain it before polling again [109]
 o-README.md: fix links [118]
 - remote-header-name.d: clarify [10]
 - runtests.pl: disable debuginfod [51]
 - runtests.pl: properly print the test if it contains binary zeros
 - runtests.pl: support the nonewline attribute for the data part [21]
 - runtests.pl: tolerate test directories without Makefile.inc [98]
 - runtests: allow client/file to specify multiple directories
 - runtests: make 'rustls' a testable feature
 - runtests: make 'wolfssl' a testable feature [6]
 - runtests: set 'oldlibssh' for libssh versions before 0.9.6 [122]
 - rustls: add CURLOPT_CAINFO_BLOB support [26]
 - scripts/cijobs.pl: output data about all currect CI jobs [78]
 - scripts/completion.pl: improve zsh completion [46]
 - scripts/copyright.pl: support many provided -ile names on the cmdline
 - scripts/delta: check the file delta for current branch
 - setopt: do bounds-check before strdup [99]
 - setopt: fix the TLSAUTH #ifdefs for proxy-disabled builds [53]
 - sha256: Fix minimum OpenSSL version [102]
 - smb: passing a socket for writing and reading data instead of FIRSTSOCKET [90]
 - test3021: disable all msys2 path transformation
 - test374: gif data without new line at the end [20]
 - tests/disable-scan.pl: properly detect multiple symbols per line [94]
 - tests/unit/Makefile.am: add NSS_LIBS to build -ith NSS fine [85]
 - tool_findfile: check ~/.config/curlrc too [17]
 - tool_getparam: DNS options that need c-ares now fail without it [31]
 - TPF: drop support [97]
 - url: exclude zonefrom_url when no ipv6 is available [103]
 - url: given a user in the URL, find pwd for that user in netrc [11]
 - url: keep trailing dot in host name [62]
 - url: make Curl_disconnect return void [48]
 - urlapi: handle "redirects" smarter [119]
 - urldata: CONN_IS_PROXIED replaces bits.close when proxy can be disabled [52]
 - urldata: remove conn->bits.user_passwd [105]
 - version_win32: fix warning for `CURL_WINDOWS_APP` [93]
 - vtls: pass on the right SNI name [61]
 - vxworks: drop support [65]
 - wolfssl: return CURLE_AGAIN for the SSL_ERROR_NONE case [106]
 - wolfssl: when SSL_read() returns zero, check the error [107]
 - write-out.d: Fix num_headers formatting
 - x509asn1: toggle off functions not needed for diff tls backends [91]

This release includes the following known bugs:

 - [see docs/KNOWN_BUGS](https://curl.se/docs/knownbugs.html)

This release would not have looked like this without help, code, reports and
advice from friends like these:

  Alejandro R. Sedeño, Alessandro Ghedini, Antoine Pietri, Bernhard Walle,
  Bjarni Ingi Gislason, Cameron Will, Charles Cazabon, Dan Fandrich,
  Daniel Stenberg, Davide Cassioli, Eric Musser, Fabian Keil, Fabian Yamaguchi,
  Filip Lundgren, gaoxingwang on github, Harry Sarson, Henrik Holst,
  Ikko Ashimine, Jan Ehrhardt, Jan-Piet Mens, jhoyla on github, John H. Ayad,
  jonny112 on github, Kantanat Wannapaka, Kevin Adler, Kushal Das,
  Leah Neukirchen, Lucas Pardue, luminixinc on github, Manfred Schwarb,
  Marcel Raad, Melroy van den Berg, Michał Antoniak, Neal McBurnett,
  neutric on github, Niels Martignène, Patrick Monnerat, pheiduck on github,
  Ray Satiro, Ryan Schmidt, Samuel Henrique, Sandro Jaeckel, Satadru Pramanik,
  Sebastian Sterk, siddharthchhabrap on github, Stav Nir, Stefan Eissing,
  Stephen Boost, Stephen M. Coakley, updatede on github, Viktor Szakats,
  Xiaoke Wang,
  (52 contributors)

References to bug reports and discussions on issues:

- [1] = https://curl.se/bug/?i=8266
- [2] = https://curl.se/bug/?i=8228
- [3] = https://curl.se/bug/?i=8228
- [4] = https://curl.se/bug/?i=8228
- [5] = https://curl.se/bug/?i=8229
- [6] = https://curl.se/bug/?i=8252
- [7] = https://curl.se/bug-?i=8262
- [8] = https://curl.se/bug/?i=8251
- [9] = https://curl.se/bug/?i=8229
- [10] = https://curl.se/bug/?i=8249
- [11] = https://curl.se/bug/?i=8241
- [12] = https://curl.se/bug/?i=8238
- [13] = https://curl.se/bug/?i=8244
- [14] = https://curl.se/bug/?i=8245
- [15] = https://curl.se/bug/?i=8240
- [16] = https://curl.se/bug/?i=8152
- [17] = https://curl.se/bug/?i=8208
- [18] = https://curl.se/bug/?i=8233
- [19] = https://curl.se/bug/?i=8234
- [20] = https://curl.se/bug/?i=8239
- [21] = https://curl.se/bug/?i=8239
- [22] = https://curl.se/bug/?i=7964
- [23] = https://curl.se/bug/?i=8188
- [24] = https://curl.se/bug/?i=8170
- [25] = https://curl.se/bug/?i=8254
- [26] = https://curl.se/bug/?i=8255
- [27] = https://curl.se/bug/?i=8286
- [28] = https://curl.se/bug/?i=8282
- [29] = https://curl.se/bug/?i=8287
- [30] = https://curl.se/bug/?i=8288
- [31] = https://curl.se/bug/?i=8285
- [32] = https://curl.se/bug/?i=8278
- [33] = https://curl.se/bug/?i=8173
- [34] = https://curl.se/bug/?i=8281
- [35] = https://curl.se/bug/?i=8279
- [36] = https://bugs.chromium.org/p/oss-fuzz/issues/detail?id=43515
- [37] = https://hackerone.com/reports/1444539
- [38] = https://curl.se/bug/?i=8321
- [39] = https://curl.se/bug/?i=8322
- [40] = https://curl.se/bug/?i=8268
- [41] = https://curl.se/bug/?i=8317
- [42] = https://curl.se/bug/?i=8315
- [43] = https://curl.se/bug/?i=8292
- [44] = https://curl.se/bug/?i=8316
- [45] = https://curl.se/bug/?i=8309
- [46] = https://curl.se/bug/?i=8363
- [47] = https://curl.se/bug/?i=8307
- [48] = https://curl.se/bug/?i=8303
- [49] = https://curl.se/bug/?i=8235
- [50] = https://curl.se/bug/?i=8299
- [51] = https://curl.se/bug/?i=8291
- [52] = https://curl.se/bug/?i=8350
- [53] = https://curl.se/bug/?i=8350
- [54] = https://curl.se/bug/?i=8276
- [55] = https://curl.se/bug/?i=8341
- [56] = https://curl.se/bug/?i=8343
- [57] = https://curl.se/bug/?i=8344
- [58] = https://curl.se/bug/?i=8340
- [59] = https://curl.se/bug/?i=8338
- [60] = https://curl.se/bug/?i=8334
- [61] = https://curl.se/bug/?i=8320
- [62] = https://curl.se/bug/?i=8290
- [63] = https://curl.se/bug/?i=8372
- [64] = https://curl.se/bug/?i=8458
- [65] = https://curl.se/bug/?i=8362
- [66] = https://curl.se/bug/?i=8460
- [67] = https://curl.se/bug/?i=8314
- [68] = https://curl.se/bug/?i=8365
- [69] = https://curl.se/bug/?i=8368
- [70] = https://curl.se/bug/?i=8367
- [71] = https://curl.se/bug/?i=8364
- [72] = https://curl.se/bug/?i=8358
- [73] = https://curl.se/bug/?i=8359
- [74] = https://curl.se/bug/?i=8357
- [75] = https://curl.se/bug/?i=8357
- [76] = https://hackerone.com/reports/1463013
- [77] = https://curl.se/bug/?i=8354
- [78] = https://curl.se/bug/?i=8408
- [79] = https://curl.se/mail/lib-2022-02/0070.html
- [80] = https://curl.se/bug/?i=8430
- [82] = https://curl.se/bug/?i=8397
- [83] = https://curl.se/bug/?i=8437
- [84] = https://curl.se/bug/?i=8396
- [85] = https://curl.se/bug/?i=8396
- [86] = https://curl.se/bug/?i=8394
- [87] = https://curl.se/bug/?i=8391
- [88] = https://curl.se/bug/?i=8381
- [89] = https://curl.se/bug/?i=8441
- [90] = https://curl.se/bug/?i=8383
- [91] = https://curl.se/bug/?i=8386
- [92] = https://curl.se/bug/?i=8428
- [93] = https://curl.se/bug/?i=8385
- [94] = https://curl.se/bug/?i=8384
- [95] = https://curl.se/bug/?i=8382
- [96] = https://curl.se/bug/?i=8378
- [97] = https://curl.se/bug/?i=8378
- [98] = https://curl.se/bug/?i=8379
- [99] = https://curl.se/bug/?i=8377
- [100] = https://curl.se/bug/?i=8376
- [101] = https://curl.se/bug/?i=8375
- [102] = https://curl.se/bug/?i=8464
- [103] = https://curl.se/bug/?i=8439
- [104] = https://curl.se/bug/?i=8439
- [105] = https://curl.se/bug/?i=8449
- [106] = https://curl.se/bug/?i=8431
- [107] = https://curl.se/bug/?i=8431
- [108] = https://curl.se/bug/?i=8436
- [109] = https://curl.se/bug/?i=8429
- [110] = https://curl.se/bug/?i=8425
- [111] = https://curl.se/bug/?i=8454
- [112] = https://curl.se/bug/?i=8454
- [113] = https://curl.se/bug/?i=8454
- [114] = https://curl.se/bug/?i=8395
- [115] = https://bugs.chromium.org/p/oss-fuzz/issues/detail?id=43646
- [116] = https://curl.se/bug/?i=8404
- [117] = https://curl.se/bug/?i=8453
- [118] = https://curl.se/bug/?i=8448
- [119] = https://curl.se/bug/?i=8450
- [121] = https://curl.se/bug/?i=8444
- [122] = https://curl.se/bug/?i=8444
- [123] = https://curl.se/bug/?i=8442
- [124] = https://curl.se/bug/?i=8438