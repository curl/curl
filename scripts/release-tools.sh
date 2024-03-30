#!/bin/sh

cat <<MOO
# Release tools

The following tools and their Debian package version numbers were used to
produce this release tarball.

MOO

exists=`which dpkg`;
if test ! -e "$exists"; then
    echo "(unknown, could not find dpkg)"
    exit
fi

debian() {
    echo - $1: `dpkg -l $1 | grep ^ii | awk '{print $3}'`
}
debian autoconf
debian automake
debian libtool
debian make
debian perl
debian git

cat <<MOO

# Reproduce the tarball

- Clone the repo and checkout the release tag
- Install the same set of tools + versions as listed above

## Do a standard build

- autoreconf -fi
- ./configure [...]
- make

## Generate the tarball

- ./maketgz [version]

MOO
