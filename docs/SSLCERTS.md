<!--
Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.

SPDX-License-Identifier: curl
-->

# TLS Certificate Verification

## Native vs file based

If curl was built with Schannel support, then curl uses the Windows native CA
store for verification. On Apple operating systems, it is possible to use Apple's
"SecTrust" services for certain TLS backends, details below.
All other TLS libraries use a file based CA store by
default.

## Verification

Every trusted server certificate is digitally signed by a Certificate
Authority, a CA.

In your local CA store you have a collection of certificates from *trusted*
certificate authorities that TLS clients like curl use to verify servers.

curl does certificate verification by default. This is done by verifying the
signature and making sure the certificate was crafted for the server name
provided in the URL.

If you communicate with HTTPS, FTPS or other TLS-using servers using
certificates signed by a CA whose certificate is present in the store, you can
be sure that the remote server really is the one it claims to be.

If the remote server uses a self-signed certificate, if you do not install a
CA cert store, if the server uses a certificate signed by a CA that is not
included in the store you use or if the remote host is an impostor
impersonating your favorite site, the certificate check fails and reports an
error.

If you think it wrongly failed the verification, consider one of the following
sections.

### Skip verification

Tell curl to *not* verify the peer with `-k`/`--insecure`.

We **strongly** recommend this is avoided and that even if you end up doing
this for experimentation or development, **never** skip verification in
production.

### Use a custom CA store

Get a CA certificate that can verify the remote server and use the proper
option to point out this CA cert for verification when connecting - for this
specific transfer only.

With the curl command line tool: `--cacert [file]`

If you use the curl command line tool without a native CA store, then you can
specify your own CA cert file by setting the environment variable
`CURL_CA_BUNDLE` to the path of your choice. `SSL_CERT_FILE` and `SSL_CERT_DIR`
are also supported.

If you are using the curl command line tool on Windows, curl searches for a CA
cert file named `curl-ca-bundle.crt` in these directories and in this order:
  1. application's directory
  2. current working directory
  3. Windows System directory (e.g. C:\Windows\System32)
  4. Windows Directory (e.g. C:\Windows)
  5. all directories along %PATH%

curl 8.11.0 added a build-time option to disable this search behavior, and
another option to restrict search to the application's directory.

### Use the native store

In several environments, in particular on Microsoft and Apple operating
systems, you can ask curl to use the system's native CA store when verifying
the certificate. Depending on how curl was built, this may already be the
default.

With the curl command line tool: `--ca-native`.

### Modify the CA store

Add the CA cert for your server to the existing default CA certificate store.

Usually you can figure out the path to the local CA store by looking at the
verbose output that `curl -v` shows when you connect to an HTTPS site.

### Change curl's default CA store

The default CA certificate store curl uses is set at build time. When you
build curl you can point out your preferred path.

### Extract CA cert from a server

    curl -w %{certs} https://example.com > cacert.pem

The certificate has `BEGIN CERTIFICATE` and `END CERTIFICATE` markers.

### Get the Mozilla CA store

Download a version of the Firefox CA store converted to PEM format on the [CA
Extract](https://curl.se/docs/caextract.html) page. It always features the
latest Firefox bundle.

## Native CA store

### Windows + Schannel

If curl was built with Schannel, then curl uses the certificates that are
built into the OS. These are the same certificates that appear in the
Internet Options control panel (under Windows).
Any custom security rules for certificates are honored.

Schannel runs CRL checks on certificates unless peer verification is disabled.

### Apple + OpenSSL/GnuTLS

When curl is built with Apple SecTrust enabled and uses an OpenSSL compatible
TLS backend or GnuTLS, the default verification is handled by that Apple
service. As in:

    curl https://example.com

You may still provide your own certificates on the command line, such as:

    curl --cacert mycerts.pem https://example.com

In this situation, Apple SecTrust is **not** used and verification is done
**only** with the trust anchors found in `mycerts.pem`. If you want **both**
Apple SecTrust and your own file to be considered, use:

    curl --ca-native --cacert mycerts.pem https://example.com

#### Other Combinations

How well the use of native CA stores work in all other combinations depends
on the TLS backend and the OS. Many TLS backends offer functionality to access
the native CA on a range of operating systems. Some provide this only on specific
configurations.

Specific support in curl exists for Windows and OpenSSL compatible TLS backends.
It tries to load the certificates from the Windows "CA" and "ROOT" stores for
transfers requesting the native CA. Due to Window's delayed population of those
stores, this might not always find all certificates.

## HTTPS proxy

curl can do HTTPS to the proxy separately from the connection to the server.
This TLS connection is handled and verified separately from the server
connection so instead of `--insecure` and `--cacert` to control the
certificate verification, you use `--proxy-insecure` and `--proxy-cacert`.
With these options, you make sure that the TLS connection and the trust of the
proxy can be kept totally separate from the TLS connection to the server.
