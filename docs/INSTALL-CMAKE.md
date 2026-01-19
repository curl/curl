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

We recommend building with CMake on Windows. For instructions on migrating
from the `projects/Windows` Visual Studio solution files, see
[this section](#migrating-from-visual-studio-ide-project-files).

## Using `cmake`

You can configure for in source tree builds or for a build tree
that is apart from the source tree.

- Build in the source tree.

      $ cmake -B .

- Build in a separate directory (parallel to the curl source tree in this
  example). The build directory is created for you. This is recommended over
  building in the source tree to separate source and build artifacts.

      $ cmake -B ../curl-build

For the full list of CMake build configuration variables see
[the corresponding section](#cmake-build-options).

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

Do not use `--prefix` to change the installation prefix as the output produced
by the `curl-config` script is determined at CMake configure time. If you want
to set a custom install prefix for curl, set
[`CMAKE_INSTALL_PREFIX`](https://cmake.org/cmake/help/latest/variable/CMAKE_INSTALL_PREFIX.html)
when configuring the CMake build.

### Fallback for CMake before version 3.15

CMake before version 3.15 does not support the `--install` option. In that
case, you have to `cd` to the build directory and use the building tool that
corresponds to the build files that CMake generated for you. This example
assumes that CMake generates `Makefile`:

    $ cd ../curl-build
    $ make install

# CMake usage

Just as curl can be built and installed using CMake, it can also be used from
CMake.

## Using `find_package`

To locate libcurl from CMake, one can use the standard
[`find_package`](https://cmake.org/cmake/help/latest/command/find_package.html)
command in the typical fashion:

```cmake
find_package(CURL 8.12.0 REQUIRED)  # FATAL_ERROR if CURL is not found
```

This invokes the CMake-provided
[FindCURL](https://cmake.org/cmake/help/latest/module/FindCURL.html) find module,
which first performs a search using the `find_package`
[config mode](https://cmake.org/cmake/help/latest/command/find_package.html#config-mode-search-procedure).
This is supported by the `CURLConfig.cmake` CMake config script which is
available if the given CURL was built and installed using CMake.

### Detecting CURL features/protocols

Since version 8.12.0, `CURLConfig.cmake` publishes the supported CURL features
and protocols (see [release notes](https://curl.se/ch/8.12.0.html)). These can
be specified using the `find_package` keywords `COMPONENTS` and
`OPTIONAL_COMPONENTS`, with protocols in all caps, e.g. `HTTPS`, `LDAP`, while
features should be in their original sentence case, e.g. `AsynchDNS`,
`UnixSockets`. If any of the `COMPONENTS` are missing, then CURL is considered
as *not* found.

Here is an example of using `COMPONENTS` and `OPTIONAL_COMPONENTS` in
`find_package` with CURL:

```cmake
# CURL_FOUND is FALSE if no HTTPS but brotli and zstd can be missing
find_package(CURL 8.12.0 COMPONENTS HTTPS OPTIONAL_COMPONENTS brotli zstd)
```

One can also check the defined `CURL_SUPPORTS_<feature-or-protocol>` variables
if a particular feature/protocol is supported. For example:

```cmake
# check HTTPS
if(CURL_SUPPORTS_HTTPS)
  message(STATUS "CURL supports HTTPS")
else()
  message(STATUS "CURL does NOT support HTTPS")
endif()
```

### Linking against libcurl

To link a CMake target against libcurl one can use
[`target_link_libraries`](https://cmake.org/cmake/help/latest/command/target_link_libraries.html)
as usual:

```cmake
target_link_libraries(my_target PRIVATE CURL::libcurl)
```

# CMake build options

- `BUILD_CURL_EXE`:                         Build curl executable. Default: `ON`
- `BUILD_EXAMPLES`:                         Build libcurl examples. Default: `ON`
- `BUILD_LIBCURL_DOCS`:                     Build libcurl man pages. Default: `ON`
- `BUILD_MISC_DOCS`:                        Build misc man pages (e.g. `curl-config` and `mk-ca-bundle`). Default: `ON`
- `BUILD_SHARED_LIBS`:                      Build shared libraries. Default: `ON` (if target platform supports shared libs, otherwise `OFF`)
- `BUILD_STATIC_CURL`:                      Build curl executable with static libcurl. Default: `OFF` (turns to `ON`, when building static libcurl only)
- `BUILD_STATIC_LIBS`:                      Build static libraries. Default: `OFF` (turns to `ON` if `BUILD_SHARED_LIBS` is `OFF`)
- `BUILD_TESTING`:                          Build tests. Default: `ON`
- `CURL_CLANG_TIDY`:                        Run the build through `clang-tidy`. Default: `OFF`
                                            If enabled, it implies `CMAKE_UNITY_BUILD=OFF` and `CURL_DISABLE_TYPECHECK=ON`.
- `CURL_CLANG_TIDYFLAGS`:                   Custom options to pass to `clang-tidy`. Default: (empty)
- `CURL_CODE_COVERAGE`:                     Enable code coverage build options. Default: `OFF`
- `CURL_COMPLETION_FISH`:                   Install fish completions. Default: `OFF`
- `CURL_COMPLETION_FISH_DIR`:               Custom fish completion install directory.
- `CURL_COMPLETION_ZSH`:                    Install zsh completions. Default: `OFF`
- `CURL_COMPLETION_ZSH_DIR`:                Custom zsh completion install directory.
- `CURL_DEFAULT_SSL_BACKEND`:               Override default TLS backend in MultiSSL builds.
                                            Accepted values in order of default priority:
                                            `wolfssl`, `gnutls`, `mbedtls`, `openssl`, `schannel`, `rustls`
- `CURL_ENABLE_EXPORT_TARGET`:              Enable CMake export target. Default: `ON`
- `CURL_HIDDEN_SYMBOLS`:                    Hide libcurl internal symbols (=hide all symbols that are not officially external). Default: `ON`
- `CURL_LIBCURL_SOVERSION`:                 Enable libcurl SOVERSION. Default: `ON` for supported platforms
- `CURL_LIBCURL_VERSIONED_SYMBOLS`:         Enable libcurl versioned symbols. Default: `OFF`
- `CURL_LIBCURL_VERSIONED_SYMBOLS_PREFIX`:  Override default versioned symbol prefix. Default: `<TLS-BACKEND>_` or `MULTISSL_`
- `CURL_LINT`:                              Run lint checks while building. Default: `OFF`
- `CURL_LTO`:                               Enable compiler Link Time Optimizations. Default: `OFF`
- `CURL_DROP_UNUSED`:                       Drop unused code and data from built binaries. Default: `OFF`
- `CURL_STATIC_CRT`:                        Build libcurl with static CRT with MSVC (`/MT`) (requires UCRT, static libcurl or no curl executable). Default: `OFF`
- `CURL_TARGET_WINDOWS_VERSION`:            Minimum target Windows version as hex string.
- `CURL_WERROR`:                            Turn compiler warnings into errors. Default: `OFF`
- `ENABLE_CURL_MANUAL`:                     Build the man page for curl and enable its `-M`/`--manual` option. Default: `ON`
- `ENABLE_DEBUG`:                           Enable curl debug features (for developing curl itself). Default: `OFF`
- `IMPORT_LIB_SUFFIX`:                      Import library suffix. Default: `_imp` for MSVC-like toolchains, otherwise empty.
- `LIBCURL_OUTPUT_NAME`:                    Basename of the curl library. Default: `libcurl`
- `PICKY_COMPILER`:                         Enable picky compiler options. Default: `ON`
- `SHARE_LIB_OBJECT`:                       Build shared and static libcurl in a single pass (requires CMake 3.12 or newer). Default: `ON` for Windows
- `STATIC_LIB_SUFFIX`:                      Static library suffix. Default: (empty)

## CA bundle options

- `CURL_CA_BUNDLE`:                         Absolute path to the CA bundle. Set `none` to disable or `auto` for auto-detection. Default: `auto`
- `CURL_CA_EMBED`:                          Absolute path to the CA bundle to embed in the curl tool. Default: (disabled)
- `CURL_CA_FALLBACK`:                       Use built-in CA store of OpenSSL. Default: `OFF`
- `CURL_CA_NATIVE`:                         Use native CA store. Default: `OFF`
                                            Supported by GnuTLS, OpenSSL (including forks) on Windows, wolfSSL.
- `CURL_CA_PATH`:                           Absolute path to a directory containing CA certificates stored individually. Set `none` to disable or `auto` for auto-detection. Default: `auto`
- `CURL_CA_SEARCH_SAFE`:                    Enable safe CA bundle search (within the curl tool directory) on Windows. Default: `OFF`

## Enabling features

- `CURL_ENABLE_SSL`:                        Enable SSL support. Default: `ON`
- `CURL_WINDOWS_SSPI`:                      Enable SSPI on Windows. Default: =`CURL_USE_SCHANNEL`
- `ENABLE_IPV6`:                            Enable IPv6 support. Default: `ON` if target supports IPv6.
- `ENABLE_THREADED_RESOLVER`:               Enable threaded DNS lookup. Default: `ON` if c-ares is not enabled and target supports threading.
- `ENABLE_UNICODE`:                         Use the Unicode version of the Windows API functions. Default: `OFF`
- `ENABLE_UNIX_SOCKETS`:                    Enable Unix domain sockets support. Default: `ON`
- `USE_ECH`:                                Enable ECH support. Default: `OFF`
- `USE_HTTPSRR`:                            Enable HTTPS RR support. Default: `OFF`
- `USE_SSLS_EXPORT`:                        Enable experimental SSL session import/export. Default: `OFF`

## Disabling features

- `CURL_DISABLE_ALTSVC`:                    Disable alt-svc support. Default: `OFF`
- `CURL_DISABLE_AWS`:                       Disable **aws-sigv4**. Default: `OFF`
- `CURL_DISABLE_BASIC_AUTH`:                Disable Basic authentication. Default: `OFF`
- `CURL_DISABLE_BEARER_AUTH`:               Disable Bearer authentication. Default: `OFF`
- `CURL_DISABLE_BINDLOCAL`:                 Disable local binding support. Default: `OFF`
- `CURL_DISABLE_CA_SEARCH`:                 Disable unsafe CA bundle search in PATH on Windows. Default: `OFF` (turns to `ON`, when `CURL_CA_NATIVE=ON`)
- `CURL_DISABLE_COOKIES`:                   Disable cookies support. Default: `OFF`
- `CURL_DISABLE_DICT`:                      Disable DICT. Default: `OFF`
- `CURL_DISABLE_DIGEST_AUTH`:               Disable Digest authentication. Default: `OFF`
- `CURL_DISABLE_DOH`:                       Disable DNS-over-HTTPS. Default: `OFF`
- `CURL_DISABLE_FILE`:                      Disable FILE. Default: `OFF`
- `CURL_DISABLE_FORM_API`:                  Disable **form-api**. Default: =`CURL_DISABLE_MIME`
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
- `CURL_DISABLE_SOCKETPAIR`:                Disable use of socketpair for curl_multi_poll(). Default: `OFF`
- `CURL_DISABLE_SRP`:                       Disable TLS-SRP support. Default: `OFF`
- `CURL_DISABLE_TELNET`:                    Disable Telnet. Default: `OFF`
- `CURL_DISABLE_TFTP`:                      Disable TFTP. Default: `OFF`
- `CURL_DISABLE_TYPECHECK`:                 Disable curl_easy_setopt()/curl_easy_getinfo() type checking. Default: `OFF`
- `CURL_DISABLE_VERBOSE_STRINGS`:           Disable verbose strings. Default: `OFF`
- `CURL_DISABLE_WEBSOCKETS`:                Disable WebSocket. Default: `OFF`
- `HTTP_ONLY`:                              Disable all protocols except HTTP (This overrides all `CURL_DISABLE_*` options). Default: `OFF`

## Environment

- `CI`:                                     Assume running under CI if set.
- `CURL_BUILDINFO`:                         Print `buildinfo.txt` if set.
- `CURL_CI`:                                Assume running under CI if set.

## CMake options

- `CMAKE_BUILD_TYPE`:                       (see CMake)
- `CMAKE_DEBUG_POSTFIX`:                    Default: `-d`
- `CMAKE_IMPORT_LIBRARY_SUFFIX`             (see CMake)
- `CMAKE_INSTALL_BINDIR`                    (see CMake)
- `CMAKE_INSTALL_INCLUDEDIR`                (see CMake)
- `CMAKE_INSTALL_LIBDIR`                    (see CMake)
- `CMAKE_INSTALL_PREFIX`                    (see CMake)
- `CMAKE_STATIC_LIBRARY_SUFFIX`             (see CMake)
- `CMAKE_UNITY_BUILD_BATCH_SIZE`:           Set the number of sources in a "unity" unit. Default: `0` (all)
- `CMAKE_UNITY_BUILD`:                      Enable "unity" (aka "jumbo") builds. Default: `OFF`

Details via CMake
[variables](https://cmake.org/cmake/help/latest/manual/cmake-variables.7.html) and
[install directories](https://cmake.org/cmake/help/latest/module/GNUInstallDirs.html).

## Dependencies

- `CURL_BROTLI`:                            Use brotli (`ON`, `OFF` or `AUTO`). Default: `AUTO`
- `CURL_USE_GNUTLS`:                        Enable GnuTLS for SSL/TLS. Default: `OFF`
- `CURL_USE_GSASL`:                         Use libgsasl. Default: `OFF`
- `CURL_USE_GSSAPI`:                        Use GSSAPI implementation. Default: `OFF`
- `CURL_USE_LIBBACKTRACE`:                  Use [libbacktrace](https://github.com/ianlancetaylor/libbacktrace). Requires debug-enabled build and DWARF debug information. Default: `OFF`
- `CURL_USE_LIBPSL`:                        Use libpsl. Default: `ON`
- `CURL_USE_LIBSSH2`:                       Use libssh2. Default: `ON`
- `CURL_USE_LIBSSH`:                        Use libssh. Default: `OFF`
- `CURL_USE_LIBUV`:                         Use libuv for event-based tests. Default: `OFF`
- `CURL_USE_MBEDTLS`:                       Enable mbedTLS for SSL/TLS. Default: `OFF`
- `CURL_USE_OPENSSL`:                       Enable OpenSSL for SSL/TLS. Default: `ON` if no other TLS backend was enabled.
- `CURL_USE_PKGCONFIG`:                     Enable `pkg-config` to detect dependencies. Default: `ON` for Unix (except Android, Apple devices), vcpkg, MinGW if not cross-compiling.
- `CURL_USE_RUSTLS`:                        Enable Rustls for SSL/TLS. Default: `OFF`
- `CURL_USE_SCHANNEL`:                      Enable Windows native SSL/TLS (Schannel). Default: `OFF`
- `CURL_USE_WOLFSSL`:                       Enable wolfSSL for SSL/TLS. Default: `OFF`
- `CURL_ZLIB`:                              Use zlib (`ON`, `OFF` or `AUTO`). Default: `AUTO`
- `CURL_ZSTD`:                              Use zstd (`ON`, `OFF` or `AUTO`). Default: `AUTO`
- `ENABLE_ARES`:                            Enable c-ares support. Default: `OFF`
- `USE_APPLE_IDN`:                          Use Apple built-in IDN support. Default: `OFF`
- `USE_APPLE_SECTRUST`:                     Use Apple OS-native certificate verification. Default: `OFF`
- `USE_LIBIDN2`:                            Use libidn2 for IDN support. Default: `ON`
- `USE_LIBRTMP`:                            Enable librtmp from rtmpdump. Default: `OFF`
- `USE_NGHTTP2`:                            Use nghttp2 library. Default: `ON`
- `USE_NGTCP2`:                             Use ngtcp2 and nghttp3 libraries for HTTP/3 support. Default: `OFF`
- `USE_QUICHE`:                             Use quiche library for HTTP/3 support. Default: `OFF`
- `USE_WIN32_IDN`:                          Use WinIDN for IDN support. Default: `OFF`
- `USE_WIN32_LDAP`:                         Use Windows LDAP implementation. Default: `ON`

## Dependency options (via CMake)

- `OPENSSL_ROOT_DIR`:                       Absolute path to the root installation of OpenSSL (and forks).
- `OPENSSL_INCLUDE_DIR`:                    Absolute path to OpenSSL include directory.
- `OPENSSL_SSL_LIBRARY`:                    Absolute path to `ssl` library. With MSVC, CMake uses variables `SSL_EAY_DEBUG`/`SSL_EAY_RELEASE` instead.
- `OPENSSL_CRYPTO_LIBRARY`:                 Absolute path to `crypto` library. With MSVC, CMake uses variables `LIB_EAY_DEBUG`/`LIB_EAY_RELEASE` instead.
- `OPENSSL_USE_STATIC_LIBS`:                Look for static OpenSSL libraries.
- `ZLIB_INCLUDE_DIR`:                       Absolute path to zlib include directory.
- `ZLIB_LIBRARY`:                           Absolute path to `zlib` library.
- `ZLIB_USE_STATIC_LIBS`:                   Look for static `zlib` library (requires CMake v3.24).

## Dependency options (tools)

- `CLANG_TIDY`:                             `clang-tidy` tool used with `CURL_CLANG_TIDY=ON`. Default: `clang-tidy`
- `PERL_EXECUTABLE`:                        Perl binary used throughout the build and tests.

## Dependency options (libraries)

- `AMISSL_INCLUDE_DIR`:                     Absolute path to AmiSSL include directory.
- `AMISSL_STUBS_LIBRARY`:                   Absolute path to `amisslstubs` library.
- `AMISSL_AUTO_LIBRARY`:                    Absolute path to `amisslauto` library.
- `BROTLI_INCLUDE_DIR`:                     Absolute path to brotli include directory.
- `BROTLICOMMON_LIBRARY`:                   Absolute path to `brotlicommon` library.
- `BROTLIDEC_LIBRARY`:                      Absolute path to `brotlidec` library.
- `CARES_INCLUDE_DIR`:                      Absolute path to c-ares include directory.
- `CARES_LIBRARY`:                          Absolute path to `cares` library.
- `DL_LIBRARY`:                             Absolute path to `dl` library. (for Rustls)
- `GNUTLS_INCLUDE_DIR`:                     Absolute path to GnuTLS include directory.
- `GNUTLS_LIBRARY`:                         Absolute path to `gnutls` library.
- `GSS_ROOT_DIR`:                           Absolute path to the root installation of GSS. (also supported as environment)
- `LDAP_INCLUDE_DIR`:                       Absolute path to LDAP include directory.
- `LDAP_LIBRARY`:                           Absolute path to `ldap` library.
- `LDAP_LBER_LIBRARY`:                      Absolute path to `lber` library.
- `LIBBACKTRACE_INCLUDE_DIR`:               Absolute path to libbacktrace include directory (https://github.com/ianlancetaylor/libbacktrace).
- `LIBBACKTRACE_LIBRARY`:                   Absolute path to `libbacktrace` library.
- `LIBGSASL_INCLUDE_DIR`:                   Absolute path to libgsasl include directory.
- `LIBGSASL_LIBRARY`:                       Absolute path to `libgsasl` library.
- `LIBIDN2_INCLUDE_DIR`:                    Absolute path to libidn2 include directory.
- `LIBIDN2_LIBRARY`:                        Absolute path to `libidn2` library.
- `LIBPSL_INCLUDE_DIR`:                     Absolute path to libpsl include directory.
- `LIBPSL_LIBRARY`:                         Absolute path to `libpsl` library.
- `LIBRTMP_INCLUDE_DIR`:                    Absolute path to librtmp include directory.
- `LIBRTMP_LIBRARY`:                        Absolute path to `librtmp` library.
- `LIBSSH_INCLUDE_DIR`:                     Absolute path to libssh include directory.
- `LIBSSH_LIBRARY`:                         Absolute path to `libssh` library.
- `LIBSSH2_INCLUDE_DIR`:                    Absolute path to libssh2 include directory.
- `LIBSSH2_LIBRARY`:                        Absolute path to `libssh2` library.
- `LIBUV_INCLUDE_DIR`:                      Absolute path to libuv include directory.
- `LIBUV_LIBRARY`:                          Absolute path to `libuv` library.
- `MATH_LIBRARY`:                           Absolute path to `m` library. (for Rustls, wolfSSL)
- `MBEDTLS_INCLUDE_DIR`:                    Absolute path to mbedTLS include directory.
- `MBEDTLS_LIBRARY`:                        Absolute path to `mbedtls` library.
- `MBEDX509_LIBRARY`:                       Absolute path to `mbedx509` library.
- `MBEDCRYPTO_LIBRARY`:                     Absolute path to `mbedcrypto` library.
- `NGHTTP2_INCLUDE_DIR`:                    Absolute path to nghttp2 include directory.
- `NGHTTP2_LIBRARY`:                        Absolute path to `nghttp2` library.
- `NGHTTP3_INCLUDE_DIR`:                    Absolute path to nghttp3 include directory.
- `NGHTTP3_LIBRARY`:                        Absolute path to `nghttp3` library.
- `NGTCP2_INCLUDE_DIR`:                     Absolute path to ngtcp2 include directory.
- `NGTCP2_LIBRARY`:                         Absolute path to `ngtcp2` library.
- `NGTCP2_CRYPTO_BORINGSSL_LIBRARY`:        Absolute path to `ngtcp2_crypto_boringssl` library. (also for AWS-LC)
- `NGTCP2_CRYPTO_GNUTLS_LIBRARY`:           Absolute path to `ngtcp2_crypto_gnutls` library.
- `NGTCP2_CRYPTO_LIBRESSL_LIBRARY`:         Absolute path to `ngtcp2_crypto_libressl` library. (requires ngtcp2 1.15.0+)
- `NGTCP2_CRYPTO_OSSL_LIBRARY`:             Absolute path to `ngtcp2_crypto_ossl` library.
- `NGTCP2_CRYPTO_QUICTLS_LIBRARY`:          Absolute path to `ngtcp2_crypto_quictls` library. (also for LibreSSL with ngtcp2 <1.15.0)
- `NGTCP2_CRYPTO_WOLFSSL_LIBRARY`:          Absolute path to `ngtcp2_crypto_wolfssl` library.
- `NETTLE_INCLUDE_DIR`:                     Absolute path to nettle include directory.
- `NETTLE_LIBRARY`:                         Absolute path to `nettle` library.
- `PTHREAD_LIBRARY`:                        Absolute path to `pthread` library. (for Rustls)
- `QUICHE_INCLUDE_DIR`:                     Absolute path to quiche include directory.
- `QUICHE_LIBRARY`:                         Absolute path to `quiche` library.
- `RUSTLS_INCLUDE_DIR`:                     Absolute path to Rustls include directory.
- `RUSTLS_LIBRARY`:                         Absolute path to `rustls` library.
- `WATT_ROOT`:                              Absolute path to the root installation of Watt-32.
- `WOLFSSL_INCLUDE_DIR`:                    Absolute path to wolfSSL include directory.
- `WOLFSSL_LIBRARY`:                        Absolute path to `wolfssl` library.
- `ZSTD_INCLUDE_DIR`:                       Absolute path to zstd include directory.
- `ZSTD_LIBRARY`:                           Absolute path to `zstd` library.

Examples:

- `-DLIBPSL_INCLUDE_DIR=/path/to/libpl/include`,
  which directory contains `libpsl.h`.
  No ending slash or backslash is necessary.

- `-DNGHTTP3_INCLUDE_DIR=/path/to/libnghttp3/include`,
  which directory contains an `nghttp3` subdirectory with `.h` files in it.

- `-DLIBPSL_LIBRARY=/path/to/libpsl/lib/libpsl.a`
  Always a single library, with its complete filename, as-is on the file system.

- `-DOPENSSL_ROOT_DIR=/path/to/openssl`,
  which directory (typically) contains `include` and `lib` subdirectories.
  No ending slash or backslash is necessary.

## Dependency options (Apple frameworks)

- `COREFOUNDATION_FRAMEWORK`:               Absolute path to `CoreFoundation` framework. (for IPv6 non-c-ares, SecTrust, wolfSSL)
- `CORESERVICES_FRAMEWORK`:                 Absolute path to `CoreServices` framework. (for IPv6 non-c-ares, SecTrust)
- `FOUNDATION_FRAMEWORK`:                   Absolute path to `Foundation` framework. (for Rustls)
- `SECURITY_FRAMEWORK`:                     Absolute path to `Security` framework. (for Rustls, SecTrust, wolfSSL)
- `SYSTEMCONFIGURATION_FRAMEWORK`:          Absolute path to `SystemConfiguration` framework. (for IPv6 non-c-ares)

## Test tools

- `APXS`:                                   Default: `apxs`
- `CADDY`:                                  Default: `caddy`
- `HTTPD_NGHTTPX`:                          Default: `nghttpx`
- `HTTPD`:                                  Default: `apache2`
- `DANTED`:                                 Default: `danted`
- `TEST_NGHTTPX`:                           Default: `nghttpx`
- `VSFTPD`:                                 Default: `vsftps`
- `SSHD`:                                   Default: `sshd`
- `SFTPD`:                                  Default: `sftp-server`

## Feature detection variables

By default this CMake build script detects the version of some dependencies
using `check_symbol_exists`. Those checks do not work in the case that both
CURL and its dependency are included as sub-projects in a larger build using
`FetchContent`. To support that case, additional variables may be defined by
the parent project, ideally in the "extra" find package redirect file:
<https://cmake.org/cmake/help/latest/module/FetchContent.html#integrating-with-find-package>

Available variables:

- `HAVE_DES_ECB_ENCRYPT`:                   `DES_ecb_encrypt` present in OpenSSL (or fork).
- `HAVE_GNUTLS_SRP`:                        `gnutls_srp_verifier` present in GnuTLS.
- `HAVE_LDAP_INIT_FD`:                      `ldap_init_fd` present in LDAP library.
- `HAVE_LDAP_URL_PARSE`:                    `ldap_url_parse` present in LDAP library.
- `HAVE_MBEDTLS_DES_CRYPT_ECB`:             `mbedtls_des_crypt_ecb` present in mbedTLS <4.
- `HAVE_OPENSSL_SRP`:                       `SSL_CTX_set_srp_username` present in OpenSSL (or fork).
- `HAVE_QUICHE_CONN_SET_QLOG_FD`:           `quiche_conn_set_qlog_fd` present in quiche.
- `HAVE_RUSTLS_SUPPORTED_HPKE`:             `rustls_supported_hpke` present in Rustls (unused if Rustls is detected via `pkg-config`).
- `HAVE_SSL_SET0_WBIO`:                     `SSL_set0_wbio` present in OpenSSL (or fork).
- `HAVE_SSL_SET1_ECH_CONFIG_LIST`:          `SSL_set1_ech_config_list` present in OpenSSL (or fork).
- `HAVE_SSL_SET_QUIC_TLS_CBS`:              `SSL_set_quic_tls_cbs` in OpenSSL.
- `HAVE_SSL_SET_QUIC_USE_LEGACY_CODEPOINT`: `SSL_set_quic_use_legacy_codepoint` in OpenSSL fork.
- `HAVE_WOLFSSL_BIO_NEW`:                   `wolfSSL_BIO_new` present in wolfSSL.
- `HAVE_WOLFSSL_BIO_SET_SHUTDOWN`:          `wolfSSL_BIO_set_shutdown` present in wolfSSL.
- `HAVE_WOLFSSL_CTX_GENERATEECHCONFIG`:     `wolfSSL_CTX_GenerateEchConfig` present in wolfSSL.
- `HAVE_WOLFSSL_DES_ECB_ENCRYPT`:           `wolfSSL_DES_ecb_encrypt` present in wolfSSL.
- `HAVE_WOLFSSL_GET_PEER_CERTIFICATE`:      `wolfSSL_get_peer_certificate` present in wolfSSL.
- `HAVE_WOLFSSL_SET_QUIC_USE_LEGACY_CODEPOINT`:
                                            `wolfSSL_set_quic_use_legacy_codepoint` present in wolfSSL.
- `HAVE_WOLFSSL_USEALPN`:                   `wolfSSL_UseALPN` present in wolfSSL.

For each of the above variables, if the variable is *defined* (either to `ON`
or `OFF`), the symbol detection is skipped. If the variable is *not defined*,
the feature detection is performed.

Note: These variables are internal and subject to change.

## Useful build targets

- `testdeps`:               Build test dependencies (servers, tools, test certificates).
                            Individual targets: `curlinfo`, `libtests`, `servers`, `tunits`, `units`
                            Test certificates: `build-certs`, `clean-certs`
- `tests`:                  Run tests (`runtests.pl`). Customize via the `TFLAGS` environment variable, e.g. `TFLAGS=1621`.
                            Other flavors: `test-am`, `test-ci`, `test-event`, `test-full`, `test-nonflaky`, `test-quiet`, `test-torture`
- `curl-pytest`:            Run tests (pytest).
                            Other flavor: `curl-test-ci`
- `curl-examples`:          Build examples
                            Individual targets: `curl-example-<name>`,
                            where <name> is the .c filename without extension.
- `curl-examples-build`:    Build examples quickly but without the ability to run them (for build tests)
- `curl-man`:               Build man pages (built by default unless disabled)
- `curl_uninstall`:         Uninstall curl
- `curl-completion-fish`:   Build shell completions for fish (built by default if enabled)
- `curl-completion-zsh`:    Build shell completions for zsh (built by default if enabled)
- `curl-ca-bundle`:         Build the CA bundle via `scripts/mk-ca-bundle.pl`
- `curl-ca-firefox`:        Build the CA bundle via `scripts/firefox-db2pem.sh`
- `curl-lint`:              Run lint checks.
- `curl-listcats`:          Generate help category constants for `src/tool_help.h` from documentation.
- `curl-listhelp`:          Generate `src/tool_listhelp.c` from documentation.
- `curl-optiontable`:       Generate `lib/easyoptions.c` from documentation.

# Migrating from Visual Studio IDE Project Files

We recommend using CMake to build curl with MSVC.

The project build files reside in project/Windows/VC\* for VS2010, VS2012 and
VS2013.

These CMake Visual Studio generators require CMake v3.24 or older. You can
download them from <https://cmake.org/files/v3.24/>.

You can also use `-G "NMake Makefiles"`, which is supported by all CMake
versions.

Configuration element             | Equivalent CMake options
:-------------------------------- | :--------------------------------
`VC10`                            | `-G "Visual Studio 10 2010"`
`VC11`                            | `-G "Visual Studio 11 2012"`
`VC12`                            | `-G "Visual Studio 12 2013"`
`x64`                             | `-A x64`
`Win32`                           | `-A Win32`
`DLL`                             | `BUILD_SHARED_LIBS=ON`, `BUILD_STATIC_LIBS=OFF`, (default)
`LIB`                             | `BUILD_SHARED_LIBS=OFF`, `BUILD_STATIC_LIBS=ON`
`Debug`                           | `CMAKE_BUILD_TYPE=Debug` (`-G "NMake Makefiles"` only)
`Release`                         | `CMAKE_BUILD_TYPE=Release` (`-G "NMake Makefiles"` only)
`DLL Windows SSPI`                | `CURL_USE_SCHANNEL=ON` (with SSPI enabled by default)
`DLL OpenSSL`                     | `CURL_USE_OPENSSL=ON`, optional: `OPENSSL_ROOT_DIR`, `OPENSSL_USE_STATIC_LIBS=ON`
`DLL libssh2`                     | `CURL_USE_LIBSSH2=ON`, optional: `LIBSSH2_INCLUDE_DIR`, `LIBSSH2_LIBRARY`
`DLL WinIDN`                      | `USE_WIN32_IDN=ON`

For example these commands:

    > cd projects/Windows
    > ./generate.bat VC12
    > msbuild "-property:Configuration=DLL Debug - DLL Windows SSPI - DLL WinIDN" VC12/curl-all.sln

translate to:

    > cmake . -G "Visual Studio 12 2013" -A x64 -DCURL_USE_SCHANNEL=ON -DUSE_WIN32_IDN=ON -DCURL_USE_LIBPSL=OFF
    > cmake --build . --config Debug --parallel

We do *not* specify `-DCMAKE_BUILD_TYPE=Debug` here as we might do for the
`"NMake Makefiles"` generator because the Visual Studio generators are
[multi-config generators](https://cmake.org/cmake/help/latest/prop_gbl/GENERATOR_IS_MULTI_CONFIG.html)
and therefore ignore the value of `CMAKE_BUILD_TYPE`.
