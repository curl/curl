<!--
Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.

SPDX-License-Identifier: curl
-->

# Building with CMake

This document describes how to configure, build and install curl and libcurl
from source code using the CMake build tool. To build with CMake, you of
course first have to install CMake. The minimum required version of CMake is
specified in the file `CMakeLists.txt` found in the top of the curl source
tree. Once the correct version of CMake is installed you can follow the
instructions below for the platform you are building on.

CMake builds can be configured either from the command line, or from one of
CMake's GUIs.

# Current flaws in the curl CMake build

Missing features in the CMake build:

 - Builds libcurl without large file support
 - Does not support all SSL libraries (only OpenSSL, Schannel, Secure
   Transport, and mbedTLS, WolfSSL)
 - Does not allow different resolver backends (no c-ares build support)
 - No RTMP support built
 - Does not allow build curl and libcurl debug enabled
 - Does not allow a custom CA bundle path
 - Does not allow you to disable specific protocols from the build
 - Does not find or use krb4 or GSS
 - Rebuilds test files too eagerly, but still cannot run the tests
 - Does not detect the correct `strerror_r` flavor when cross-compiling
   (issue #1123)

# Configuring

A CMake configuration of curl is similar to the autotools build of curl.
It consists of the following steps after you have unpacked the source.

## Using `cmake`

You can configure for in source tree builds or for a build tree
that is apart from the source tree.

 - Build in the source tree.

       $ cmake -B .

 - Build in a separate directory (parallel to the curl source tree in this
   example). The build directory is created for you.

       $ cmake -B ../curl-build

### Fallback for CMake before version 3.13

CMake before version 3.13 does not support the `-B` option. In that case,
you must create the build directory yourself, `cd` to it and run `cmake`
from there:

    $ mkdir ../curl-build
    $ cd ../curl-build
    $ cmake ../curl

If you want to build in the source tree, it is enough to do this:

    $ cmake .

### Build system generator selection

You can override CMake's default by using `-G <generator-name>`. For example
on Windows with multiple build systems if you have MinGW-w64 then you could use
`-G "MinGW Makefiles"`.
[List of generator names](https://cmake.org/cmake/help/latest/manual/cmake-generators.7.html).

## Using `ccmake`

CMake comes with a curses based interface called `ccmake`. To run `ccmake`
on a curl use the instructions for the command line cmake, but substitute
`ccmake` for `cmake`.

This brings up a curses interface with instructions on the bottom of the
screen. You can press the "c" key to configure the project, and the "g" key to
generate the project. After the project is generated, you can run make.

## Using `cmake-gui`

CMake also comes with a Qt based GUI called `cmake-gui`. To configure with
`cmake-gui`, you run `cmake-gui` and follow these steps:

 1. Fill in the "Where is the source code" combo box with the path to
    the curl source tree.
 2. Fill in the "Where to build the binaries" combo box with the path to
    the directory for your build tree, ideally this should not be the same
    as the source tree, but a parallel directory called curl-build or
    something similar.
 3. Once the source and binary directories are specified, press the
    "Configure" button.
 4. Select the native build tool that you want to use.
 5. At this point you can change any of the options presented in the GUI.
    Once you have selected all the options you want, click the "Generate"
    button.

# Building

Build (you have to specify the build directory).

    $ cmake --build ../curl-build

### Fallback for CMake before version 3.13

CMake before version 3.13 does not support the `--build` option. In that
case, you have to `cd` to the build directory and use the building tool that
corresponds to the build files that CMake generated for you. This example
assumes that CMake generates `Makefile`:

    $ cd ../curl-build
    $ make

# Testing

(The test suite does not yet work with the cmake build)

# Installing

Install to default location (you have to specify the build directory).

    $ cmake --install ../curl-build

### Fallback for CMake before version 3.15

CMake before version 3.15 does not support the `--install` option. In that
case, you have to `cd` to the build directory and use the building tool that
corresponds to the build files that CMake generated for you. This example
assumes that CMake generates `Makefile`:

    $ cd ../curl-build
    $ make install
