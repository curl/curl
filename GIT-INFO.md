<!--
Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.

SPDX-License-Identifier: curl
-->
                                  _   _ ____  _
                              ___| | | |  _ \| |
                             / __| | | | |_) | |
                            | (__| |_| |  _ <| |___
                             \___|\___/|_| \_\_____|

# GIT-INFO

This file is only present in git - never in release archives. It contains
information about other files and things that the git repository keeps in its
inner sanctum.

To build in environments that support configure, after having extracted
everything from git, do this:

    autoreconf -fi
    ./configure --with-openssl
    make

Daniel uses a configure line similar to this for easier development:

    ./configure --disable-shared --enable-debug --enable-maintainer-mode

## Tests may fail to build due to old autotools

Automake 1.15 and possibly older versions has a bug that causes it to create
bad dependency tracking files for the tests and as a result `make test` fails.
To remedy that either set the environment to use a more recent version of
automake before running autoreconf, or configure with option
`--disable-dependency-tracking`.

## REQUIREMENTS

See [docs/DEPENDENCIES.md][0] for requirement details.

[0]: docs/DEPENDENCIES.md
