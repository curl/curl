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

In environments that don't support configure (i.e. Windows), do this:

    buildconf.bat

## REQUIREMENTS

For `autoreconf` and `configure` (not `buildconf.bat`) to work, you need the
following software installed:

 - autoconf 2.57  (or later)
 - automake 1.7   (or later)
 - libtool  1.4.2 (or later)
 - GNU m4 (required by autoconf)
 - perl     5.8.0 (or later)

If you don't have perl and don't want to install it, you can rename the source
file `src/tool_hugehelp.c.cvs` to `src/tool_hugehelp.c` and avoid having to
generate this file. This will give you a stubbed version of the file that
doesn't contain actual content.
