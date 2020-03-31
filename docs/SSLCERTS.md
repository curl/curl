SSL Certificate Verification
============================

SSL is TLS
----------

SSL is the old name. It is called TLS these days.


Native SSL
----------

If libcurl was built with Schannel or Secure Transport support (the native SSL
libraries included in Windows and Mac OS X), then this does not apply to
you. Scroll down for details on how the OS-native engines handle SSL
certificates. If you're not sure, then run "curl -V" and read the results. If
the version string says "WinSSL" in it, then it was built with Schannel
support.

It is about trust
-----------------

This system is about trust. In your local CA certificate store you have certs
from *trusted* Certificate Authorities that you then can use to verify that the
server certificates you see are valid. They're signed by one of the CAs you
trust.

Which CAs do you trust? You can decide to trust the same set of companies your
operating system trusts, or the set one of the known browsers trust. That's
basically trust via someone else you trust. You should just be aware that
modern operating systems and browsers are setup to trust *hundreds* of
companies and recent years several such CAs have been found untrustworthy.

Certificate Verification
------------------------

libcurl performs peer SSL certificate verification by default.  This is done
by using a CA certificate store that the SSL library can use to make sure the
peer's server certificate is valid.

If you communicate with HTTPS, FTPS or other TLS-using servers using
certificates that are signed by CAs present in the store, you can be sure
that the remote server really is the one it claims to be.

If the remote server uses a self-signed certificate, if you don't install a CA
cert store, if the server uses a certificate signed by a CA that isn't
included in the store you use or if the remote host is an impostor
impersonating your favorite site, and you want to transfer files from this
server, do one of the following:

 1. Tell libcurl to *not* verify the peer. With libcurl you disable this with
    `curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, FALSE);`

    With the curl command line tool, you disable this with -k/--insecure.

 2. Get a CA certificate that can verify the remote server and use the proper
    option to point out this CA cert for verification when connecting. For
    libcurl hackers: `curl_easy_setopt(curl, CURLOPT_CAINFO, cacert);`

    With the curl command line tool: --cacert [file]

 3. Add the CA cert for your server to the existing default CA certificate
    store. The default CA certificate store can changed at compile time with the
    following configure options:

    --with-ca-bundle=FILE: use the specified file as CA certificate store. CA
    certificates need to be concatenated in PEM format into this file.

    --with-ca-path=PATH: use the specified path as CA certificate store. CA
    certificates need to be stored as individual PEM files in this directory.
    You may need to run c_rehash after adding files there.

    If neither of the two options is specified, configure will try to auto-detect
    a setting. It's also possible to explicitly not hardcode any default store
    but rely on the built in default the crypto library may provide instead.
    You can achieve that by passing both --without-ca-bundle and
    --without-ca-path to the configure script.

    If you use Internet Explorer, this is one way to get extract the CA cert
    for a particular server:

     - View the certificate by double-clicking the padlock
     - Find out where the CA certificate is kept (Certificate>
       Authority Information Access>URL)
     - Get a copy of the crt file using curl
     - Convert it from crt to PEM using the openssl tool:
       openssl x509 -inform DES -in yourdownloaded.crt \
       -out outcert.pem -text
     - Add the 'outcert.pem' to the CA certificate store or use it stand-alone
       as described below.

    If you use the 'openssl' tool, this is one way to get extract the CA cert
    for a particular server:

     - `openssl s_client -showcerts -servername server -connect server:443 > cacert.pem`
     - type "quit", followed by the "ENTER" key
     - The certificate will have "BEGIN CERTIFICATE" and "END CERTIFICATE"
       markers.
     - If you want to see the data in the certificate, you can do: "openssl
       x509 -inform PEM -in certfile -text -out certdata" where certfile is
       the cert you extracted from logfile. Look in certdata.
     - If you want to trust the certificate, you can add it to your CA
       certificate store or use it stand-alone as described. Just remember that
       the security is no better than the way you obtained the certificate.

 4. If you're using the curl command line tool, you can specify your own CA
    cert file by setting the environment variable `CURL_CA_BUNDLE` to the path
    of your choice.

    If you're using the curl command line tool on Windows, curl will search
    for a CA cert file named "curl-ca-bundle.crt" in these directories and in
    this order:
      1. application's directory
      2. current working directory
      3. Windows System directory (e.g. C:\windows\system32)
      4. Windows Directory (e.g. C:\windows)
      5. all directories along %PATH%

 5. Get a better/different/newer CA cert bundle! One option is to extract the
    one a recent Firefox browser uses by running 'make ca-bundle' in the curl
    build tree root, or possibly download a version that was generated this
    way for you: [CA Extract](https://curl.haxx.se/docs/caextract.html)

Neglecting to use one of the above methods when dealing with a server using a
certificate that isn't signed by one of the certificates in the installed CA
certificate store, will cause SSL to report an error ("certificate verify
failed") during the handshake and SSL will then refuse further communication
with that server.

Certificate Verification with NSS
---------------------------------

If libcurl was built with NSS support, then depending on the OS distribution,
it is probably required to take some additional steps to use the system-wide
CA cert db. RedHat ships with an additional module, libnsspem.so, which
enables NSS to read the OpenSSL PEM CA bundle. On openSUSE you can install
p11-kit-nss-trust which makes NSS use the system wide CA certificate store. NSS
also has a new [database format](https://wiki.mozilla.org/NSS_Shared_DB).

Starting with version 7.19.7, libcurl automatically adds the 'sql:' prefix to
the certdb directory (either the hardcoded default /etc/pki/nssdb or the
directory configured with SSL_DIR environment variable). To check which certdb
format your distribution provides, examine the default certdb location:
/etc/pki/nssdb; the new certdb format can be identified by the filenames
cert9.db, key4.db, pkcs11.txt; filenames of older versions are cert8.db,
key3.db, secmod.db.

Certificate Verification with Schannel and Secure Transport
-----------------------------------------------------------

If libcurl was built with Schannel (Microsoft's native TLS engine) or Secure
Transport (Apple's native TLS engine) support, then libcurl will still perform
peer certificate verification, but instead of using a CA cert bundle, it will
use the certificates that are built into the OS. These are the same
certificates that appear in the Internet Options control panel (under Windows)
or Keychain Access application (under OS X). Any custom security rules for
certificates will be honored.

Schannel will run CRL checks on certificates unless peer verification is
disabled. Secure Transport on iOS will run OCSP checks on certificates unless
peer verification is disabled. Secure Transport on OS X will run either OCSP
or CRL checks on certificates if those features are enabled, and this behavior
can be adjusted in the preferences of Keychain Access.

HTTPS proxy
-----------

Since version 7.52.0, curl can do HTTPS to the proxy separately from the
connection to the server. This TLS connection is handled separately from the
server connection so instead of `--insecure` and `--cacert` to control the
certificate verification, you use `--proxy-insecure` and `--proxy-cacert`.
With these options, you make sure that the TLS connection and the trust of the
proxy can be kept totally separate from the TLS connection to the server.
