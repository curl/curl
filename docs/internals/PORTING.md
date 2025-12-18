<!--
Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.

SPDX-License-Identifier: curl
-->

# porting libcurl

The basic approach I use when porting libcurl to another OS when the existing
configure or cmake build setups are not suitable.

## Build

Write a build script/Makefile that builds *all* C files under lib/. If
possible, use the `lib/Makefile.inc` that lists all files in Makefile
variables.

In the Makefile, make sure you define what OS you build for: `-D[OPERATING
SYSTEM]`, or similar. Perhaps the compiler in use already define a standard
one? Then you might not need to define your own.

## Add the new OS

In the `lib/curl_config.h` header file, in the section for when `HAVE_CONFIG_H`
is *not* defined (starting at around line 150), add a new conditional include
in this style:

~~~c
#ifdef [OPERATING SYSTEM]
#  include "config-operatingsystem.h"
#endif
~~~

Create `lib/config-operatingsystem.h`. You might want to start with copying a
another config-* file and then start trimming according to what your
environment supports.

## Build it

When you run into compiler warnings or errors, the
`lib/config-operatingsystem.h` file should be where you should focus your work
and edits.

A recommended approach is to define a lot of the `CURL_DISABLE_*` defines (see
the [CURL-DISABLE](../CURL-DISABLE.md) document) initially to help narrow down
the initial work as that can save you from having to give attention to areas of
the code that you do not care for in your port.
