---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: fetch_version_info
Section: 3
Source: libfetch
See-also:
  - fetch_version (3)
Protocol:
  - All
Added-in: 7.10.0
---

# NAME

fetch_version_info - returns runtime libfetch version info

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

fetch_version_info_data *fetch_version_info(FETCHversion age);
~~~

# DESCRIPTION

Returns a pointer to a filled in static struct with information about various
features in the running version of libfetch. *age* should be set to the
version of this functionality by the time you write your program. This way,
libfetch always returns a proper struct that your program understands, while
programs in the future might get a different struct. **FETCHVERSION_NOW** is
the most recent one for the library you have installed:
~~~c
  data = fetch_version_info(FETCHVERSION_NOW);
~~~
Applications should use this information to judge if things are possible to do
or not, instead of using compile-time checks, as dynamic/DLL libraries can be
changed independent of applications.

This function can alter the returned static data as long as
fetch_global_init(3) has not been called. It is therefore not thread-safe
before libfetch initialization occurs.

The fetch_version_info_data struct looks like this

~~~c
typedef struct {
  FETCHversion age;          /* see description below */

  const char *version;      /* human readable string */
  unsigned int version_num; /* numeric representation */
  const char *host;         /* human readable string */
  int features;             /* bitmask, see below */
  char *ssl_version;        /* human readable string */
  long ssl_version_num;     /* not used, always zero */
  const char *libz_version; /* human readable string */
  const char *const *protocols; /* protocols */

  /* when 'age' is FETCHVERSION_SECOND or higher, the members below exist */
  const char *ares;         /* human readable string */
  int ares_num;             /* number */

  /* when 'age' is FETCHVERSION_THIRD or higher, the members below exist */
  const char *libidn;       /* human readable string */

  /* when 'age' is FETCHVERSION_FOURTH or higher (>= 7.16.1), the members
     below exist */
  int iconv_ver_num;       /* '_libiconv_version' if iconv support enabled */

  const char *libssh_version; /* human readable string */

  /* when 'age' is FETCHVERSION_FIFTH or higher (>= 7.57.0), the members
     below exist */
  unsigned int brotli_ver_num; /* Numeric Brotli version
                                  (MAJOR << 24) | (MINOR << 12) | PATCH */
  const char *brotli_version; /* human readable string. */

  /* when 'age' is FETCHVERSION_SIXTH or higher (>= 7.66.0), the members
     below exist */
  unsigned int nghttp2_ver_num; /* Numeric nghttp2 version
                                   (MAJOR << 16) | (MINOR << 8) | PATCH */
  const char *nghttp2_version; /* human readable string. */

  const char *quic_version;    /* human readable quic (+ HTTP/3) library +
                                  version or NULL */

  /* when 'age' is FETCHVERSION_SEVENTH or higher (>= 7.70.0), the members
     below exist */
  const char *cainfo;          /* the built-in default FETCHOPT_CAINFO, might
                                  be NULL */
  const char *capath;          /* the built-in default FETCHOPT_CAPATH, might
                                  be NULL */
  /* when 'age' is FETCHVERSION_EIGHTH or higher (>= 7.71.0), the members
     below exist */
  unsigned int zstd_ver_num; /* Numeric Zstd version
                                  (MAJOR << 24) | (MINOR << 12) | PATCH */
  const char *zstd_version; /* human readable string. */
  /* when 'age' is FETCHVERSION_NINTH or higher (>= 7.75.0), the members
     below exist */
  const char *hyper_version; /* human readable string. */
  /* when 'age' is FETCHVERSION_TENTH or higher (>= 7.77.0), the members
     below exist */
  const char *gsasl_version; /* human readable string. */
  /* when 'age' is FETCHVERSION_ELEVENTH or higher (>= 7.87.0), the members
     below exist */
  const char *const *feature_names; /* Feature names. */
  /* when 'age' is FETCHVERSION_TWELFTH or higher (>= 8.8.0), the members
     below exist */
  const char *const *rtmp_version; /* human readable string */
} fetch_version_info_data;
~~~

*age* describes what the age of this struct is. The number depends on how
new the libfetch you are using is. You are however guaranteed to get a struct
that you have a matching struct for in the header, as you tell libfetch your
"age" with the input argument.

*version* is just an ASCII string for the libfetch version.

*version_num* is a 24 bit number created like this: \<8 bits major number\> |
\<8 bits minor number\> | \<8 bits patch number\>. Version 7.9.8 is therefore
returned as 0x070908.

*host* is an ASCII string showing what host information that this libfetch
was built for. As discovered by a configure script or set by the build
environment.

*features* is a bit mask representing available features. It can have none,
one or more bits set. The use of this field is deprecated: use
*feature_names* instead. The feature names description below lists the
associated bits.

*feature_names* is a pointer to an array of string pointers, containing the
names of the features that libfetch supports. The array is terminated by a NULL
entry. See the list of features names below.

*ssl_version* is an ASCII string for the TLS library name + version used. If
libfetch has no SSL support, this is NULL. For example "Schannel", "Secure
Transport" or "OpenSSL/1.1.0g".

*ssl_version_num* is always 0.

*libz_version* is an ASCII string (there is no numerical version). If
libfetch has no libz support, this is NULL.

*protocols* is a pointer to an array of char * pointers, containing the
names protocols that libfetch supports (using lowercase letters). The protocol
names are the same as would be used in URLs. The array is terminated by a NULL
entry.

# FEATURES

## `alt-svc`

*features* mask bit: FETCH_VERSION_ALTSVC

HTTP Alt-Svc parsing and the associated options (Added in 7.64.1)

## `AsynchDNS`

*features* mask bit: FETCH_VERSION_ASYNCHDNS

libfetch was built with support for asynchronous name lookups, which allows
more exact timeouts (even on Windows) and less blocking when using the multi
interface. (added in 7.10.7)

## `brotli`

*features* mask bit: FETCH_VERSION_BROTLI

supports HTTP Brotli content encoding using libbrotlidec (Added in 7.57.0)

## `asyn-rr`

*features* mask bit: non-existent

libfetch was built to use c-ares for EXPERIMENTAL HTTPS resource record
resolves, but uses the threaded resolver for "normal" resolves (Added in
8.12.0)

## `Debug`

*features* mask bit: FETCH_VERSION_DEBUG

libfetch was built with debug capabilities (added in 7.10.6)

## `ECH`

*features* mask bit: non-existent

libfetch was built with ECH support (experimental, added in 8.8.0)

## `gsasl`

*features* mask bit: FETCH_VERSION_GSASL

libfetch was built with libgsasl and thus with some extra SCRAM-SHA
authentication methods. (added in 7.76.0)

## `GSS-API`

*features* mask bit: FETCH_VERSION_GSSAPI

libfetch was built with support for GSS-API. This makes libfetch use provided
functions for Kerberos and SPNEGO authentication. It also allows libfetch
to use the current user credentials without the app having to pass them on.
(Added in 7.38.0)

## `HSTS`

*features* mask bit: FETCH_VERSION_HSTS

libfetch was built with support for HSTS (HTTP Strict Transport Security)
(Added in 7.74.0)

## `HTTP2`

*features* mask bit: FETCH_VERSION_HTTP2

libfetch was built with support for HTTP2.
(Added in 7.33.0)

## `HTTP3`

*features* mask bit: FETCH_VERSION_HTTP3

HTTP/3 and QUIC support are built-in (Added in 7.66.0)

## `HTTPS-proxy`

*features* mask bit: FETCH_VERSION_HTTPS_PROXY

libfetch was built with support for HTTPS-proxy.
(Added in 7.52.0)

## `HTTPSRR`

*features* mask bit: non-existent

libfetch was built with EXPERIMENTAL support for HTTPS resource records (Added
in 8.12.0)

## `IDN`

*features* mask bit: FETCH_VERSION_IDN

libfetch was built with support for IDNA, domain names with international
letters. (Added in 7.12.0)

## `IPv6`

*features* mask bit: FETCH_VERSION_IPV6

supports IPv6

## `Kerberos`

*features* mask bit: FETCH_VERSION_KERBEROS5

supports Kerberos V5 authentication for FTP, IMAP, LDAP, POP3, SMTP and
SOCKSv5 proxy. (Added in 7.40.0)

## `Largefile`

*features* mask bit: FETCH_VERSION_LARGEFILE

libfetch was built with support for large files. (Added in 7.11.1)

## `libz`

*features* mask bit: FETCH_VERSION_LIBZ

supports HTTP deflate using libz (Added in 7.10)

## `MultiSSL`

*features* mask bit: FETCH_VERSION_MULTI_SSL

libfetch was built with multiple SSL backends. For details, see
fetch_global_sslset(3).
(Added in 7.56.0)

## `NTLM`

*features* mask bit: FETCH_VERSION_NTLM

supports HTTP NTLM (added in 7.10.6)

## `NTLM_WB`

*features* mask bit: FETCH_VERSION_NTLM_WB

libfetch was built with support for NTLM delegation to a winbind helper.
(Added in 7.22.0) This feature was removed from fetch in 8.8.0.

## `PSL`

*features* mask bit: FETCH_VERSION_PSL

libfetch was built with support for Mozilla's Public Suffix List. This makes
libfetch ignore cookies with a domain that is on the list.
(Added in 7.47.0)

## `SPNEGO`

*features* mask bit: FETCH_VERSION_SPNEGO

libfetch was built with support for SPNEGO authentication (Simple and Protected
GSS-API Negotiation Mechanism, defined in RFC 2478.) (added in 7.10.8)

## `SSL`

*features* mask bit: FETCH_VERSION_SSL

supports SSL (HTTPS/FTPS) (Added in 7.10)

## `SSLS-EXPORT`

*features* mask bit: non-existent

libfetch was built with SSL session import/export support
(experimental, added in 8.12.0)

## `SSPI`

*features* mask bit: FETCH_VERSION_SSPI

libfetch was built with support for SSPI. This is only available on Windows and
makes libfetch use Windows-provided functions for Kerberos, NTLM, SPNEGO and
Digest authentication. It also allows libfetch to use the current user
credentials without the app having to pass them on. (Added in 7.13.2)

## `threadsafe`

*features* mask bit: FETCH_VERSION_THREADSAFE

libfetch was built with thread-safety support (Atomic or SRWLOCK) to protect
fetch initialization. (Added in 7.84.0) See libfetch-thread(3)

## `TLS-SRP`

*features* mask bit: FETCH_VERSION_TLSAUTH_SRP

libfetch was built with support for TLS-SRP (in one or more of the built-in TLS
backends). (Added in 7.21.4)

## `TrackMemory`

*features* mask bit: FETCH_VERSION_FETCHDEBUG

libfetch was built with memory tracking debug capabilities. This is mainly of
interest for libfetch hackers. (added in 7.19.6)

## `Unicode`

*features* mask bit: FETCH_VERSION_UNICODE

libfetch was built with Unicode support on Windows. This makes non-ASCII
characters work in filenames and options passed to libfetch. (Added in 7.72.0)

## `UnixSockets`

*features* mask bit: FETCH_VERSION_UNIX_SOCKETS

libfetch was built with support for Unix domain sockets.
(Added in 7.40.0)

## `zstd`

*features* mask bit: FETCH_VERSION_ZSTD

supports HTTP zstd content encoding using zstd library (Added in 7.72.0)

## no name

*features* mask bit: FETCH_VERSION_CONV

libfetch was built with support for character conversions, as provided by the
FETCHOPT_CONV_* callbacks. Always 0 since 7.82.0. (Added in 7.15.4,
deprecated.)

## no name

*features* mask bit: FETCH_VERSION_GSSNEGOTIATE

supports HTTP GSS-Negotiate (added in 7.10.6, deprecated in 7.38.0)

## no name

*features* mask bit: FETCH_VERSION_KERBEROS4

supports Kerberos V4 (when using FTP). Legacy bit. Deprecated since 7.33.0.

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  fetch_version_info_data *ver = fetch_version_info(FETCHVERSION_NOW);
  printf("libfetch version %u.%u.%u\n",
         (ver->version_num >> 16) & 0xff,
         (ver->version_num >> 8) & 0xff,
         ver->version_num & 0xff);
}
~~~

# %AVAILABILITY%

# RETURN VALUE

A pointer to a fetch_version_info_data struct.
