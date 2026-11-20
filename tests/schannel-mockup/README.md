# Schannel Mockup Library (OpenSSL Backend)

This directory contains a mockup implementation of the Windows Security
Support Provider Interface (SSPI) Schannel and CryptoAPI interfaces for
non-Windows platforms, backed by OpenSSL under the hood.

It allows libcurl's native Schannel backend (`lib/vtls/schannel.c` and
`lib/vtls/schannel_verify.c`) to build, run, and execute full test suites on
Linux, macOS, and BSD systems.

## Source code

The code is should be usable as an Schannel replacement without touching curl
source code.

It should remain C89 compliant, stay within 80 columns and otherwise stick
to curl's code style.

## Use with curl

### build schannel-mockup

    $ autoreconf -fi
    $ ./configure --prefix=/install/path/
    $ make
    $ make install

Alternatively, build and keep it in-tree:

    $ autoreconf -fi
    $ ./configure
    $ make
    $ ln -s .libs lib

### build curl to use schannel-mockup

    $ configure --schannel-mockup=/install/path

Or if the build is in-tree:

    $ configure --schannel-mockup=`pwd`/tests/schannel-mockup
