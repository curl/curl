                                  _   _ ____  _
                              ___| | | |  _ \| |
                             / __| | | | |_) | |
                            | (__| |_| |  _ <| |___
                             \___|\___/|_| \_\_____|

# SSL problems

  First, let's establish that we often refer to TLS and SSL interchangeably as
  SSL here. The current protocol is called TLS, it was called SSL a long time
  ago.

  There are several known reasons why a connection that involves SSL might
  fail. This is a document that attempts to details the most common ones and
  how to mitigate them.

## CA certs

  CA certs are used to digitally verify the server's certificate. You need a
  "ca bundle" for this. See lots of more details on this in the SSLCERTS
  document.

## CA bundle missing intermediate certificates

  When using said CA bundle to verify a server cert, you will experience
  problems if your CA cert does not have the certificates for the
  intermediates in the whole trust chain.

## Protocol version

  Some broken servers fail to support the protocol negotiation properly that
  SSL servers are supposed to handle. This may cause the connection to fail
  completely. Sometimes you may need to explicitly select a SSL version to use
  when connecting to make the connection succeed.

  An additional complication can be that modern SSL libraries sometimes are
  built with support for older SSL and TLS versions disabled!

  All versions of SSL are considered insecure and should be avoided. Use TLS.

## Ciphers

  Clients give servers a list of ciphers to select from. If the list doesn't
  include any ciphers the server wants/can use, the connection handshake
  fails.

  curl has recently disabled the user of a whole bunch of seriously insecure
  ciphers from its default set (slightly depending on SSL backend in use).

  You may have to explicitly provide an alternative list of ciphers for curl
  to use to allow the server to use a WEAK cipher for you.

  Note that these weak ciphers are identified as flawed. For example, this
  includes symmetric ciphers with less than 128 bit keys and RC4.

  Schannel in Windows XP is not able to connect to servers that no longer
  support the legacy handshakes and algorithms used by those versions, so we
  advice against building curl to use Schannel on really old Windows versions.

  References:

  https://tools.ietf.org/html/draft-popov-tls-prohibiting-rc4-01

## Allow BEAST

  BEAST is the name of a TLS 1.0 attack that surfaced 2011. When adding means
  to mitigate this attack, it turned out that some broken servers out there in
  the wild didn't work properly with the BEAST mitigation in place.

  To make such broken servers work, the --ssl-allow-beast option was
  introduced. Exactly as it sounds, it re-introduces the BEAST vulnerability
  but on the other hand it allows curl to connect to that kind of strange
  servers.

## Disabling certificate revocation checks

  Some SSL backends may do certificate revocation checks (CRL, OCSP, etc)
  depending on the OS or build configuration. The --ssl-no-revoke option was
  introduced in 7.44.0 to disable revocation checking but currently is only
  supported for Schannel (the native Windows SSL library), with an exception
  in the case of Windows' Untrusted Publishers block list which it seems can't
  be bypassed. This option may have broader support to accommodate other SSL
  backends in the future.

  References:

  https://curl.haxx.se/docs/ssl-compared.html
