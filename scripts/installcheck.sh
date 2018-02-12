#!/bin/bash

PREFIX=$1

# Run this script in the root of the git clone. Point out the install prefix
# where 'make install' has already installed curl.

if test -z "$1";  then
    echo "scripts/installcheck.sh [PREFIX]"
    exit
fi

diff -u <(find docs/libcurl/ -name "*.3" -printf "%f\n" | grep -v template| sort) <(find $PREFIX/share/man/ -name "*.3" -printf "%f\n" | sort)

if test "$?" -ne "0"; then
    echo "ERROR: installed libcurl docs mismatch"
    exit 2
fi

diff -u <(find include/ -name "*.h" -printf "%f\n" | sort) <(find $PREFIX/include/ -name "*.h" -printf "%f\n" | sort)

if test "$?" -ne "0"; then
    echo "ERROR: installed include files mismatch"
    exit 1
fi

echo "installcheck: installed libcurl docs and include files look good"
