---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: mk-ca-bundle
Section: 1
Source: mk-ca-bundle
See-also:
  - curl (1)
Added-in: n/a
---

# NAME

mk-ca-bundle - convert Mozilla's certificate bundle to PEM format

# SYNOPSIS

mk-ca-bundle [options] [output]

# DESCRIPTION

This tool downloads the *certdata.txt* file from Mozilla's source tree over
HTTPS, then parses it and extracts the included certificates into PEM format.
By default, only CA root certificates trusted to issue SSL server
authentication certificates are extracted. These are then processed with the
OpenSSL command line tool to produce the final ca-bundle output file.

The default *output* name is **ca-bundle.crt**. By setting it to '-' (a single
dash) you get the output sent to STDOUT instead of a file.

The PEM format this scripts uses for output makes the result readily available
for use by just about all OpenSSL or GnuTLS powered applications, such as curl
and others.

# OPTIONS

The following options are supported:

## -b

backup an existing version of *output*

## -d [name]

specify which Mozilla tree to pull *certdata.txt* from (or a custom URL).
Valid names are: **aurora**, **beta**, **central**, **Mozilla**, **nss**,
**release** (default). They are shortcuts for which source tree to get the
certificate data from.

## -f

force rebuild even if *certdata.txt* is current (Added in version 1.17)

## -i

print version info about used modules

## -k

Allow insecure data transfer. By default (since 1.27) this command fails if
the HTTPS transfer fails. This overrides that decision (and opens for
man-in-the-middle attacks).

## -l

print license info about *certdata.txt*

## -m

(Added in 1.26) Include meta data comments in the output. The meta data is
specific information about each certificate that is stored in the original
file as comments and using this option makes those comments get passed on to
the output file. The meta data is not parsed in any way by mk-ca-bundle.

## -n

Do not download *certdata.txt* - use the existing.

## -p [purposes]:[levels]

list of Mozilla trust purposes and levels for certificates to include in
output. Takes the form of a comma separated list of purposes, a colon, and a
comma separated list of levels. The default is to include all certificates
trusted to issue SSL Server certificates (*SERVER_AUTH:TRUSTED_DELEGATOR*).

Valid purposes are: **ALL**, **DIGITAL_SIGNATURE**, **NON_REPUDIATION**,
**KEY_ENCIPHERMENT**, **DATA_ENCIPHERMENT**, **KEY_AGREEMENT**,
**KEY_CERT_SIGN**, **CRL_SIGN**, **SERVER_AUTH** (default), **CLIENT_AUTH**,
**CODE_SIGNING**, **EMAIL_PROTECTION**, **IPSEC_END_SYSTEM**,
**IPSEC_TUNNEL**, **IPSEC_USER**, **TIME_STAMPING**, **STEP_UP_APPROVED**

Valid trust levels are: **ALL**, **TRUSTED_DELEGATOR** (default), **NOT_TRUSTED**,
**MUST_VERIFY_TRUST**, **TRUSTED**

## -q

be really quiet (no progress output at all)

## -t

include plain text listing of certificates

## -s [algorithms]

A comma separated list of signature algorithms with which to hash/fingerprint
each certificate and output when run in plain text mode.

Valid algorithms are:
ALL, NONE, MD5 (default), SHA1, SHA256, SHA384, SHA512

## -u

unlink (remove) *certdata.txt* after processing

## -v

be verbose and print out processed certificate authorities

# EXIT STATUS

Returns 0 on success. Returns 1 if it fails to download data.

# FILE FORMAT

The file format used by Mozilla for this trust information is documented here:

https://p11-glue.freedesktop.org/doc/storing-trust-policy/storing-trust-existing.html
