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

## REQUIREMENTS

See [docs/INTERNALS.md][0] for requirement details.

[0]: docs/INTERNALS.md
