<!--
Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.

SPDX-License-Identifier: curl
-->

# Building with CMake

This document describes how to configure, build and install curl and libcurl
from source code using the CMake build tool. To build with CMake, you of
course first have to install CMake. The minimum required version of CMake is
specified in the file `CMakeLists.txt` found in the top of the curl source
tree. Once the correct version of CMake is installed you can follow the
instructions below for the platform you are building on.

CMake builds can be configured either from the command line, or from one of
CMake's GUIs.

# Configuring

A CMake configuration of curl is similar to the autotools build of curl.
It consists of the following steps after you have unpacked the source.

## Using `cmake`

You can configure for in source tree builds or for a build tree
that is apart from the source tree.

 - Build in the source tree.

       $ cmake -B .

 - Build in a separate directory (parallel to the curl source tree in this
   example). The build directory is created for you.

       $ cmake -B ../curl-build

### Fallback for CMake before version 3.13

CMake before version 3.13 does not support the `-B` option. In that case,
you must create the build directory yourself, `cd` to it and run `cmake`
from there:

    $ mkdir ../curl-build
    $ cd ../curl-build
    $ cmake ../curl

If you want to build in the source tree, it is enough to do this:

    $ cmake .

### Build system generator selection

You can override CMake's default by using `-G <generator-name>`. For example
on Windows with multiple build systems if you have MinGW-w64 then you could use
`-G "MinGW Makefiles"`.
[List of generator names](https://cmake.org/cmake/help/latest/manual/cmake-generators.7.html).

## Using `ccmake`

CMake comes with a curses based interface called `ccmake`. To run `ccmake`
on a curl use the instructions for the command line cmake, but substitute
`ccmake` for `cmake`.

This brings up a curses interface with instructions on the bottom of the
screen. You can press the "c" key to configure the project, and the "g" key to
generate the project. After the project is generated, you can run make.

## Using `cmake-gui`

CMake also comes with a Qt based GUI called `cmake-gui`. To configure with
`cmake-gui`, you run `cmake-gui` and follow these steps:

 1. Fill in the "Where is the source code" combo box with the path to
    the curl source tree.
 2. Fill in the "Where to build the binaries" combo box with the path to
    the directory for your build tree, ideally this should not be the same
    as the source tree, but a parallel directory called curl-build or
    something similar.
 3. Once the source and binary directories are specified, press the
    "Configure" button.
 4. Select the native build tool that you want to use.
 5. At this point you can change any of the options presented in the GUI.
    Once you have selected all the options you want, click the "Generate"
    button.

# Building

Build (you have to specify the build directory).

    $ cmake --build ../curl-build

## Static builds

The CMake build setup is primarily done to work with shared/dynamic third
party dependencies. When linking with shared libraries, the dependency "chain"
is handled automatically by the library loader - on all modern systems.

If you instead link with a static library, you need to provide all the
dependency libraries already at the link command line.

Figuring out all the dependency libraries for a given library is hard, as it
might involve figuring out the dependencies of the dependencies and they vary
between platforms and can change between versions.

When using static dependencies, the build scripts mostly assume that you, the
user, provide all the necessary additional dependency libraries as additional
arguments in the build.

Building statically is not for the faint of heart.

### Fallback for CMake before version 3.13

CMake before version 3.13 does not support the `--build` option. In that
case, you have to `cd` to the build directory and use the building tool that
corresponds to the build files that CMake generated for you. This example
assumes that CMake generates `Makefile`:

    $ cd ../curl-build
    $ make

# Testing

(The test suite does not yet work with the cmake build)

# Installing

Install to default location (you have to specify the build directory).

    $ cmake --install ../curl-build

### Fallback for CMake before version 3.15

CMake before version 3.15 does not support the `--install` option. In that
case, you have to `cd` to the build directory and use the building tool that
corresponds to the build files that CMake generated for you. This example
assumes that CMake generates `Makefile`:

    $ cd ../curl-build
    $ make install

# CMake build options

- `BUILD_CURL_EXE`:                         Build curl executable. Default: `ON`
- `BUILD_EXAMPLES`:                         Build libcurl examples. Default: `ON`
- `BUILD_LIBCURL_DOCS`:                     Build libcurl man pages. Default: `ON`
- `BUILD_MISC_DOCS`:                        Build misc man pages (e.g. `curl-config` and `mk-ca-bundle`). Default: `ON`
- `BUILD_SHARED_LIBS`:                      Build shared libraries. Default: `ON`
- `BUILD_STATIC_CURL`:                      Build curl executable with static libcurl. Default: `OFF`
- `BUILD_STATIC_LIBS`:                      Build static libraries. Default: `OFF`
- `BUILD_TESTING`:                          Build tests. Default: `ON`
- `CURL_DEFAULT_SSL_BACKEND`:               Override default TLS backend in MultiSSL builds.
                                            Accepted values in order of default priority:
                                            `wolfssl`, `gnutls`, `mbedtls`, `openssl`, `secure-transport`, `schannel`, `bearssl`, `rustls`
- `CURL_ENABLE_EXPORT_TARGET`:              Enable CMake export target. Default: `ON`
- `CURL_HIDDEN_SYMBOLS`:                    Hide libcurl internal symbols (=hide all symbols that are not officially external). Default: `ON`
- `CURL_LIBCURL_SOVERSION`:                 Enable libcurl SOVERSION. Default: `ON` for supported platforms
- `CURL_LIBCURL_VERSIONED_SYMBOLS`:         Enable libcurl versioned symbols. Default: `OFF`
- `CURL_LIBCURL_VERSIONED_SYMBOLS_PREFIX`:  Override default versioned symbol prefix. Default: `<TLS-BACKEND>_` or `MULTISSL_`
- `CURL_LTO`:                               Enable compiler Link Time Optimizations. Default: `OFF`
- `CURL_STATIC_CRT`:                        Build libcurl with static CRT with MSVC (`/MT`). Default: `OFF`
- `CURL_TARGET_WINDOWS_VERSION`:            Minimum target Windows version as hex string.
- `CURL_TEST_BUNDLES`:                      Bundle `libtest` and `unittest` tests into single binaries. Default: `OFF`
- `CURL_WERROR`:                            Turn compiler warnings into errors. Default: `OFF`
- `ENABLE_CURLDEBUG`:                       Enable TrackMemory debug feature: Default: =`ENABLE_DEBUG`
- `ENABLE_CURL_MANUAL`:                     Build the man page for curl and enable its `-M`/`--manual` option. Default: `ON`
- `ENABLE_DEBUG`:                           Enable curl debug features (for developing curl itself). Default: `OFF`
- `IMPORT_LIB_SUFFIX`:                      Import library suffix. Default: `_imp`
- `LIBCURL_OUTPUT_NAME`:                    Basename of the curl library. Default: `libcurl`
- `PICKY_COMPILER`:                         Enable picky compiler options. Default: `ON`
- `STATIC_LIB_SUFFIX`:                      Static library suffix. Default: (empty)

## CA bundle options

- `CURL_CA_BUNDLE`:                         Path to the CA bundle. Set `none` to disable or `auto` for auto-detection. Default: `auto`
- `CURL_CA_EMBED`:                          Path to the CA bundle to embed in the curl tool. Default: (disabled)
- `CURL_CA_FALLBACK`:                       Use built-in CA store of TLS backend. Default: `OFF`
- `CURL_CA_PATH`:                           Location of default CA path. Set `none` to disable or `auto` for auto-detection. Default: `auto`
- `CURL_CA_SEARCH_SAFE`:                    Enable safe CA bundle search (within the curl tool directory) on Windows. Default: `OFF`

## Enabling features

- `CURL_ENABLE_SSL`:                        Enable SSL support. Default: `ON`
- `CURL_WINDOWS_SSPI`:                      Enable SSPI on Windows. Default: =`CURL_USE_SCHANNEL`
- `ENABLE_IPV6`:                            Enable IPv6 support. Default: `ON`
- `ENABLE_THREADED_RESOLVER`:               Enable threaded DNS lookup. Default: `ON` if c-ares is not enabled
- `ENABLE_UNICODE`:                         Use the Unicode version of the Windows API functions. Default: `OFF`
- `ENABLE_UNIX_SOCKETS`:                    Enable Unix domain sockets support. Default: `ON`
- `USE_ECH`:                                Enable ECH support. Default: `OFF`
- `USE_HTTPSRR`:                            Enable HTTPS RR support for ECH (experimental). Default: `OFF`
- `USE_OPENSSL_QUIC`:                       Use OpenSSL and nghttp3 libraries for HTTP/3 support. Default: `OFF`

## Disabling features

- `CURL_DISABLE_ALTSVC`:                    Disable alt-svc support. Default: `OFF`
- `CURL_DISABLE_AWS`:                       Disable **aws-sigv4**. Default: `OFF`
- `CURL_DISABLE_BASIC_AUTH`:                Disable Basic authentication. Default: `OFF`
- `CURL_DISABLE_BEARER_AUTH`:               Disable Bearer authentication. Default: `OFF`
- `CURL_DISABLE_BINDLOCAL`:                 Disable local binding support. Default: `OFF`
- `CURL_DISABLE_CA_SEARCH`:                 Disable unsafe CA bundle search in PATH on Windows. Default: `OFF`
- `CURL_DISABLE_COOKIES`:                   Disable cookies support. Default: `OFF`
- `CURL_DISABLE_DICT`:                      Disable DICT. Default: `OFF`
- `CURL_DISABLE_DIGEST_AUTH`:               Disable Digest authentication. Default: `OFF`
- `CURL_DISABLE_DOH`:                       Disable DNS-over-HTTPS. Default: `OFF`
- `CURL_DISABLE_FILE`:                      Disable FILE. Default: `OFF`
- `CURL_DISABLE_FORM_API`:                  Disable **form-api**: Default: =`CURL_DISABLE_MIME`
- `CURL_DISABLE_FTP`:                       Disable FTP. Default: `OFF`
- `CURL_DISABLE_GETOPTIONS`:                Disable `curl_easy_options` API for existing options to `curl_easy_setopt`. Default: `OFF`
- `CURL_DISABLE_GOPHER`:                    Disable Gopher. Default: `OFF`
- `CURL_DISABLE_HEADERS_API`:               Disable **headers-api** support. Default: `OFF`
- `CURL_DISABLE_HSTS`:                      Disable HSTS support. Default: `OFF`
- `CURL_DISABLE_HTTP`:                      Disable HTTP. Default: `OFF`
- `CURL_DISABLE_HTTP_AUTH`:                 Disable all HTTP authentication methods. Default: `OFF`
- `CURL_DISABLE_IMAP`:                      Disable IMAP. Default: `OFF`
- `CURL_DISABLE_INSTALL`:                   Disable installation targets. Default: `OFF`
- `CURL_DISABLE_IPFS`:                      Disable IPFS. Default: `OFF`
- `CURL_DISABLE_KERBEROS_AUTH`:             Disable Kerberos authentication. Default: `OFF`
- `CURL_DISABLE_LDAP`:                      Disable LDAP. Default: `OFF`
- `CURL_DISABLE_LDAPS`:                     Disable LDAPS. Default: =`CURL_DISABLE_LDAP`
- `CURL_DISABLE_LIBCURL_OPTION`:            Disable `--libcurl` option from the curl tool. Default: `OFF`
- `CURL_DISABLE_MIME`:                      Disable MIME support. Default: `OFF`
- `CURL_DISABLE_MQTT`:                      Disable MQTT. Default: `OFF`
- `CURL_DISABLE_NEGOTIATE_AUTH`:            Disable negotiate authentication. Default: `OFF`
- `CURL_DISABLE_NETRC`:                     Disable netrc parser. Default: `OFF`
- `CURL_DISABLE_NTLM`:                      Disable NTLM support. Default: `OFF`
- `CURL_DISABLE_OPENSSL_AUTO_LOAD_CONFIG`:  Disable automatic loading of OpenSSL configuration. Default: `OFF`
- `CURL_DISABLE_PARSEDATE`:                 Disable date parsing. Default: `OFF`
- `CURL_DISABLE_POP3`:                      Disable POP3. Default: `OFF`
- `CURL_DISABLE_PROGRESS_METER`:            Disable built-in progress meter. Default: `OFF`
- `CURL_DISABLE_PROXY`:                     Disable proxy support. Default: `OFF`
- `CURL_DISABLE_RTSP`:                      Disable RTSP. Default: `OFF`
- `CURL_DISABLE_SHA512_256`:                Disable SHA-512/256 hash algorithm. Default: `OFF`
- `CURL_DISABLE_SHUFFLE_DNS`:               Disable shuffle DNS feature. Default: `OFF`
- `CURL_DISABLE_SMB`:                       Disable SMB. Default: `OFF`
- `CURL_DISABLE_SMTP`:                      Disable SMTP. Default: `OFF`
- `CURL_DISABLE_SOCKETPAIR`:                Disable use of socketpair for curl_multi_poll. Default: `OFF`
- `CURL_DISABLE_SRP`:                       Disable TLS-SRP support. Default: `OFF`
- `CURL_DISABLE_TELNET`:                    Disable Telnet. Default: `OFF`
- `CURL_DISABLE_TFTP`:                      Disable TFTP. Default: `OFF`
- `CURL_DISABLE_VERBOSE_STRINGS`:           Disable verbose strings. Default: `OFF`
- `CURL_DISABLE_WEBSOCKETS`:                Disable WebSocket. Default: `OFF`
- `HTTP_ONLY`:                              Disable all protocols except HTTP (This overrides all `CURL_DISABLE_*` options). Default: `OFF`

## Environment

- `CI`:                                     Assume running under CI if set.
- `CURL_BUILDINFO`:                         Print `buildinfo.txt` if set.
- `CURL_CI`:                                Assume running under CI if set.

## CMake options

- `CMAKE_DEBUG_POSTFIX`:                    Default: `-d`
- `CMAKE_IMPORT_LIBRARY_SUFFIX`             (see CMake)
- `CMAKE_INSTALL_BINDIR`                    (see CMake)
- `CMAKE_INSTALL_INCLUDEDIR`                (see CMake)
- `CMAKE_INSTALL_LIBDIR`                    (see CMake)
- `CMAKE_INSTALL_PREFIX`                    (see CMake)
- `CMAKE_STATIC_LIBRARY_SUFFIX`             (see CMake)
- `CMAKE_UNITY_BUILD_BATCH_SIZE`:           Set the number of sources in a "unity" unit. Default: `0` (all)
- `CMAKE_UNITY_BUILD`:                      Enable "unity" (aka jumbo) builds. Default: `OFF`

Details via CMake
[variables](https://cmake.org/cmake/help/latest/manual/cmake-variables.7.html) and
[install directories](https://cmake.org/cmake/help/latest/module/GNUInstallDirs.html).

## Dependencies

- `CURL_BROTLI`:                            Use brotli. Default: `OFF`
- `CURL_USE_BEARSSL`:                       Enable BearSSL for SSL/TLS. Default: `OFF`
- `CURL_USE_GNUTLS`:                        Enable GnuTLS for SSL/TLS. Default: `OFF`
- `CURL_USE_GSASL`:                         Use libgsasl. Default: `OFF`
- `CURL_USE_GSSAPI`:                        Use GSSAPI implementation. Default: `OFF`
- `CURL_USE_LIBPSL`:                        Use libpsl. Default: `ON`
- `CURL_USE_LIBSSH2`:                       Use libssh2. Default: `ON`
- `CURL_USE_LIBSSH`:                        Use libssh. Default: `OFF`
- `CURL_USE_LIBUV`:                         Use libuv for event-based tests. Default: `OFF`
- `CURL_USE_MBEDTLS`:                       Enable mbedTLS for SSL/TLS. Default: `OFF`
- `CURL_USE_OPENSSL`:                       Enable OpenSSL for SSL/TLS. Default: `ON` if no other TLS backend was enabled.
- `CURL_USE_PKGCONFIG`:                     Enable `pkg-config` to detect dependencies. Default: `ON` for Unix, vcpkg, MinGW if not cross-compiling.
- `CURL_USE_RUSTLS`:                        Enable Rustls for SSL/TLS. Default: `OFF`
- `CURL_USE_SCHANNEL`:                      Enable Windows native SSL/TLS (Schannel). Default: `OFF`
- `CURL_USE_SECTRANSP`:                     Enable Apple OS native SSL/TLS (Secure Transport). Default: `OFF`
- `CURL_USE_WOLFSSH`:                       Use wolfSSH. Default: `OFF`
- `CURL_USE_WOLFSSL`:                       Enable wolfSSL for SSL/TLS. Default: `OFF`
- `CURL_ZLIB`:                              Use zlib (`ON`, `OFF` or `AUTO`). Default: `AUTO`
- `CURL_ZSTD`:                              Use zstd. Default: `OFF`
- `ENABLE_ARES`:                            Enable c-ares support. Default: `OFF`
- `USE_APPLE_IDN`:                          Use Apple built-in IDN support. Default: `OFF`
- `USE_LIBIDN2`:                            Use libidn2 for IDN support. Default: `ON`
- `USE_LIBRTMP`:                            Enable librtmp from rtmpdump. Default: `OFF`
- `USE_MSH3`:                               Use msh3/msquic library for HTTP/3 support. Default: `OFF`
- `USE_NGHTTP2`:                            Use nghttp2 library. Default: `ON`
- `USE_NGTCP2`:                             Use ngtcp2 and nghttp3 libraries for HTTP/3 support. Default: `OFF`
- `USE_QUICHE`:                             Use quiche library for HTTP/3 support. Default: `OFF`
- `USE_WIN32_IDN`:                          Use WinIDN for IDN support. Default: `OFF`
- `USE_WIN32_LDAP`:                         Use Windows LDAP implementation. Default: `ON`

## Dependency options (via CMake)

- `OPENSSL_ROOT_DIR`:                       Set this variable to the root installation of OpenSSL (and forks).
- `ZLIB_INCLUDE_DIR`:                       The zlib include directory.
- `ZLIB_LIBRARY`:                           Path to `zlib` library.

## Dependency options

- `PERL_EXECUTABLE`                         Perl binary used throughout the build and tests.
- `BEARSSL_INCLUDE_DIR`:                    The BearSSL include directory.
- `BEARSSL_LIBRARY`:                        Path to `bearssl` library.
- `BROTLI_INCLUDE_DIR`:                     The brotli include directory.
- `BROTLICOMMON_LIBRARY`:                   Path to `brotlicommon` library.
- `BROTLIDEC_LIBRARY`:                      Path to `brotlidec` library.
- `CARES_INCLUDE_DIR`:                      The c-ares include directory.
- `CARES_LIBRARY`:                          Path to `cares` library.
- `GSS_ROOT_DIR`:                           Set this variable to the root installation of GSS. (also supported as environment)
- `LDAP_LIBRARY`:                           Name or full path to `ldap` library. Default: `ldap`
- `LDAP_LBER_LIBRARY`:                      Name or full path to `lber` library. Default: `lber`
- `LDAP_INCLUDE_DIR`:                       Path to LDAP include directory.
- `LIBGSASL_INCLUDE_DIR`:                   The libgsasl include directory.
- `LIBGSASL_LIBRARY`:                       Path to `libgsasl` library.
- `LIBIDN2_INCLUDE_DIR`:                    The libidn2 include directory.
- `LIBIDN2_LIBRARY`:                        Path to `libidn2` library.
- `LIBPSL_INCLUDE_DIR`:                     The libpsl include directory.
- `LIBPSL_LIBRARY`:                         Path to `libpsl` library.
- `LIBSSH_INCLUDE_DIR`:                     The libssh include directory.
- `LIBSSH_LIBRARY`:                         Path to `libssh` library.
- `LIBSSH2_INCLUDE_DIR`:                    The libssh2 include directory.
- `LIBSSH2_LIBRARY`:                        Path to `libssh2` library.
- `LIBUV_INCLUDE_DIR`:                      The libuv include directory.
- `LIBUV_LIBRARY`:                          Path to `libuv` library.
- `MSH3_INCLUDE_DIR`:                       The msh3 include directory.
- `MSH3_LIBRARY`:                           Path to `msh3` library.
- `MBEDTLS_INCLUDE_DIR`:                    The mbedTLS include directory.
- `MBEDTLS_LIBRARY`:                        Path to `mbedtls` library.
- `MBEDX509_LIBRARY`:                       Path to `mbedx509` library.
- `MBEDCRYPTO_LIBRARY`:                     Path to `mbedcrypto` library.
- `NGHTTP2_INCLUDE_DIR`:                    The nghttp2 include directory.
- `NGHTTP2_LIBRARY`:                        Path to `nghttp2` library.
- `NGHTTP3_INCLUDE_DIR`:                    The nghttp3 include directory.
- `NGHTTP3_LIBRARY`:                        Path to `nghttp3` library.
- `NGTCP2_INCLUDE_DIR`:                     The ngtcp2 include directory.
- `NGTCP2_LIBRARY`:                         Path to `ngtcp2` library.
- `NETTLE_INCLUDE_DIR`:                     The nettle include directory.
- `NETTLE_LIBRARY`:                         Path to `nettle` library.
- `QUICHE_INCLUDE_DIR`:                     The quiche include directory.
- `QUICHE_LIBRARY`:                         Path to `quiche` library.
- `RUSTLS_INCLUDE_DIR`:                     The Rustls include directory.
- `RUSTLS_LIBRARY`:                         Path to `rustls` library.
- `WOLFSSH_INCLUDE_DIR`:                    The wolfSSH include directory.
- `WOLFSSH_LIBRARY`:                        Path to `wolfssh` library.
- `WOLFSSL_INCLUDE_DIR`:                    The wolfSSL include directory.
- `WOLFSSL_LIBRARY`:                        Path to `wolfssl` library.
- `ZSTD_INCLUDE_DIR`:                       The zstd include directory.
- `ZSTD_LIBRARY`:                           Path to `zstd` library.

## Test tools

- `APACHECTL`:                              Default: `apache2ctl`
- `APXS`:                                   Default: `apxs`
- `CADDY`:                                  Default: `caddy`
- `HTTPD_NGHTTPX`:                          Default: `nghttpx`
- `HTTPD`:                                  Default: `apache2`
- `TEST_NGHTTPX`:                           Default: `nghttpx`
- `VSFTPD`:                                 Default: `vsftps`
