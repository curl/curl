<!--
Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.

SPDX-License-Identifier: curl
-->

# TLS Certificate Verification

## Native vs file based

If curl was built with Schannel or Secure Transport support, then curl uses
the system native CA store for verification. All other TLS libraries use a
file based CA store by default.

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
`CURL_CA_BUNDLE` to the path of your choice.

If you are using the curl command line tool on Windows, curl searches for a CA
cert file named `curl-ca-bundle.crt` in these directories and in this order:
  1. application's directory
  2. current working directory
  3. Windows System directory (e.g. C:\Windows\System32)
  4. Windows Directory (e.g. C:\Windows)
  5. all directories along %PATH%

### Use the native store

In several environments, in particular on Windows, you can ask curl to use the
system's native CA store when verifying the certificate.

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

If curl was built with Schannel, Secure Transport or were instructed to use
the native CA Store, then curl uses the certificates that are built into the
OS. These are the same certificates that appear in the Internet Options
control panel (under Windows) or Keychain Access application (under macOS).
Any custom security rules for certificates are honored.

Schannel runs CRL checks on certificates unless peer verification is disabled.
Secure Transport on iOS runs OCSP checks on certificates unless peer
verification is disabled. Secure Transport on macOS runs either OCSP or CRL
checks on certificates if those features are enabled, and this behavior can be
adjusted in the preferences of Keychain Access.

## HTTPS proxy

curl can do HTTPS to the proxy separately from the connection to the server.
This TLS connection is handled and verified separately from the server
connection so instead of `--insecure` and `--cacert` to control the
certificate verification, you use `--proxy-insecure` and `--proxy-cacert`.
With these options, you make sure that the TLS connection and the trust of the
proxy can be kept totally separate from the TLS connection to the server.
