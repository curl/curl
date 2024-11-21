<!--
Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.

SPDX-License-Identifier: curl
-->

## curl cipher options

With curl's option
[`--tls13-ciphers`](https://curl.se/docs/manpage.html#--tls13-ciphers)
or
[`CURLOPT_TLS13_CIPHERS`](https://curl.se/libcurl/c/CURLOPT_TLS13_CIPHERS.html)
users can control which cipher suites to consider when negotiating TLS 1.3
connections. With option
[`--ciphers`](https://curl.se/docs/manpage.html#--ciphers)
or
[`CURLOPT_SSL_CIPHER_LIST`](https://curl.se/libcurl/c/CURLOPT_SSL_CIPHER_LIST.html)
users can control which cipher suites to consider when negotiating
TLS 1.2 (1.1, 1.0) connections.

By default, curl may negotiate TLS 1.3 and TLS 1.2 connections, so the cipher
suites considered when negotiating a TLS connection are a union of the TLS 1.3
and TLS 1.2 cipher suites. If you want curl to consider only TLS 1.3 cipher
suites for the connection, you have to set the minimum TLS version to 1.3 by
using [`--tlsv1.3`](https://curl.se/docs/manpage.html#--tlsv13)
or [`CURLOPT_SSLVERSION`](https://curl.se/libcurl/c/CURLOPT_SSLVERSION.html)
with `CURL_SSLVERSION_TLSv1_3`.

Both the TLS 1.3 and TLS 1.2 cipher options expect a list of cipher suites
separated by colons (`:`). This list is parsed opportunistically, cipher suites
that are not recognized or implemented are ignored. As long as there is at
least one recognized cipher suite in the list, the list is considered valid.

For both the TLS 1.3 and TLS 1.2 cipher options, the order in which the
cipher suites are specified determine the preference of them. When negotiating
a TLS connection the server picks a cipher suite from the intersection of the
cipher suites supported by the server and the cipher suites sent by curl. If
the server is configured to honor the client's cipher preference, the first
common cipher suite in the list sent by curl is chosen.

## TLS 1.3 cipher suites

Setting TLS 1.3 cipher suites is supported by curl with
OpenSSL (1.1.1+, curl 7.61.0+), LibreSSL (3.4.1+, curl 8.3.0+),
wolfSSL (curl 8.10.0+) and mbedTLS (3.6.0+, curl 8.10.0+).

The list of cipher suites that can be used for the `--tls13-ciphers` option:
```
TLS_AES_128_GCM_SHA256
TLS_AES_256_GCM_SHA384
TLS_CHACHA20_POLY1305_SHA256
TLS_AES_128_CCM_SHA256
TLS_AES_128_CCM_8_SHA256
```

### wolfSSL notes

In addition to above list the following cipher suites can be used:
`TLS_SM4_GCM_SM3` `TLS_SM4_CCM_SM3` `TLS_SHA256_SHA256` `TLS_SHA384_SHA384`.
Usage of these cipher suites is not recommended. (The last two cipher suites
are NULL ciphers, offering no encryption whatsoever.)

## TLS 1.2 (1.1, 1.0) cipher suites

Setting TLS 1.2 cipher suites is supported by curl with OpenSSL, LibreSSL,
BoringSSL, mbedTLS (curl 8.8.0+), wolfSSL (curl 7.53.0+),
Secure Transport (curl 7.77.0+) and BearSSL (curl 7.83.0+). Schannel does not
support setting cipher suites directly, but does support setting algorithms
(curl 7.61.0+), see Schannel notes below.

For TLS 1.2 cipher suites there are multiple naming schemes, the two most used
are with OpenSSL names (e.g. `ECDHE-RSA-AES128-GCM-SHA256`) and IANA names
(e.g. `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256`). IANA names of TLS 1.2 cipher
suites look similar to TLS 1.3 cipher suite names, to distinguish them note
that TLS 1.2 names contain `_WITH_`, while TLS 1.3 names do not. When setting
TLS 1.2 cipher suites with curl it is recommended that you use OpenSSL names
as these are most widely recognized by the supported SSL backends.

The complete list of cipher suites that may be considered for the `--ciphers`
option is extensive, it consists of more than 300 ciphers suites. However,
nowadays for most of them their usage is discouraged, and support for a lot of
them have been removed from the various SSL backends, if ever implemented at
all.

A shortened list (based on [recommendations by
Mozilla](https://wiki.mozilla.org/Security/Server_Side_TLS)) of cipher suites,
which are (mostly) supported by all SSL backends, that can be used for the
`--ciphers` option:
```
ECDHE-ECDSA-AES128-GCM-SHA256
ECDHE-RSA-AES128-GCM-SHA256
ECDHE-ECDSA-AES256-GCM-SHA384
ECDHE-RSA-AES256-GCM-SHA384
ECDHE-ECDSA-CHACHA20-POLY1305
ECDHE-RSA-CHACHA20-POLY1305
DHE-RSA-AES128-GCM-SHA256
DHE-RSA-AES256-GCM-SHA384
DHE-RSA-CHACHA20-POLY1305
ECDHE-ECDSA-AES128-SHA256
ECDHE-RSA-AES128-SHA256
ECDHE-ECDSA-AES128-SHA
ECDHE-RSA-AES128-SHA
ECDHE-ECDSA-AES256-SHA384
ECDHE-RSA-AES256-SHA384
ECDHE-ECDSA-AES256-SHA
ECDHE-RSA-AES256-SHA
DHE-RSA-AES128-SHA256
DHE-RSA-AES256-SHA256
AES128-GCM-SHA256
AES256-GCM-SHA384
AES128-SHA256
AES256-SHA256
AES128-SHA
AES256-SHA
DES-CBC3-SHA
```

See this [list](https://github.com/curl/curl/blob/master/docs/CIPHERS-TLS12.md)
for a complete list of TLS 1.2 cipher suites.

### OpenSSL notes

In addition to specifying a list of cipher suites, OpenSSL also accepts a
format with specific cipher strings (like `TLSv1.2`, `AESGCM`, `CHACHA20`) and
`!`, `-` and `+` operators. Refer to the
[OpenSSL cipher documentation](https://docs.openssl.org/master/man1/openssl-ciphers/#cipher-list-format)
for further information on that format.

### Schannel notes

Schannel does not support setting individual TLS 1.2 cipher suites directly.
It only allows the enabling and disabling of encryption algorithms. These are
in the form of `CALG_xxx`, see the [Schannel `ALG_ID`
documentation](https://docs.microsoft.com/windows/desktop/SecCrypto/alg-id)
for a list of these algorithms. Also, (since curl 7.77.0)
`SCH_USE_STRONG_CRYPTO` can be given to pass that flag to Schannel, lookup the
[documentation for the Windows version in
use](https://learn.microsoft.com/en-us/windows/win32/secauthn/cipher-suites-in-schannel)
to see how that affects the cipher suite selection. When not specifying the
`--chiphers` and `--tl13-ciphers` options curl passes this flag by default.

## Examples

```sh
curl \
  --tls13-ciphers TLS_AES_128_GCM_SHA256:TLS_CHACHA20_POLY1305_SHA256 \
  --ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:\
ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305 \
  https://example.com/
```
Restrict ciphers to `aes128-gcm` and `chacha20`. Works with OpenSSL, LibreSSL,
mbedTLS and wolfSSL.

```sh
curl \
  --tlsv1.3 \
  --tls13-ciphers TLS_AES_128_GCM_SHA256:TLS_CHACHA20_POLY1305_SHA256 \
  https://example.com/
```
Restrict to only TLS 1.3 with `aes128-gcm` and `chacha20` ciphers. Works with
OpenSSL, LibreSSL, mbedTLS, wolfSSL and Schannel.

```sh
curl \
  --ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:\
ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305 \
  https://example.com/
```
Restrict TLS 1.2 ciphers to `aes128-gcm` and `chacha20`, use default TLS 1.3
ciphers (if TLS 1.3 is available). Works with OpenSSL, LibreSSL, BoringSSL,
mbedTLS, wolfSSL, Secure Transport and BearSSL.

## Further reading
- [OpenSSL cipher suite names documentation](https://docs.openssl.org/master/man1/openssl-ciphers/#cipher-suite-names)
- [wolfSSL cipher support documentation](https://www.wolfssl.com/documentation/manuals/wolfssl/chapter04.html#cipher-support)
- [mbedTLS cipher suites reference](https://mbed-tls.readthedocs.io/projects/api/en/development/api/file/ssl__ciphersuites_8h/)
- [Schannel cipher suites documentation](https://learn.microsoft.com/en-us/windows/win32/secauthn/cipher-suites-in-schannel)
- [BearSSL supported crypto](https://www.bearssl.org/support.html)
- [Secure Transport cipher suite values](https://developer.apple.com/documentation/security/1550981-ssl_cipher_suite_values)
- [IANA cipher suites list](https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-4)
- [Wikipedia cipher suite article](https://en.wikipedia.org/wiki/Cipher_suite)
