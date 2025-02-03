---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: fetch-config
Section: 1
Source: fetch-config
See-also:
  - fetch (1)
Added-in: 7.7.2
---

# NAME

fetch-config - Get information about a libfetch installation

# SYNOPSIS

**fetch-config [options]**

# DESCRIPTION

**fetch-config**
displays information about the fetch and libfetch installation.

# OPTIONS

## --ca

Displays the built-in path to the CA cert bundle this libfetch uses.

## --cc

Displays the compiler used to build libfetch.

## --cflags

Set of compiler options (CFLAGS) to use when compiling files that use
libfetch. Currently that is only the include path to the fetch include files.

## --checkfor [version]

Specify the oldest possible libfetch version string you want, and this script
returns 0 if the current installation is new enough or it returns 1 and
outputs a text saying that the current version is not new enough. (Added in
7.15.4)

## --configure

Displays the arguments given to configure when building fetch.

## --feature

Lists what particular main features the installed libfetch was built with. At
the time of writing, this list may include SSL, KRB4 or IPv6. Do not assume
any particular order. The keywords are separated by newlines. There may be
none, one, or several keywords in the list.

## --help

Displays the available options.

## --libs

Shows the complete set of libs and other linker options you need in order to
link your application with libfetch.

## --prefix

This is the prefix used when libfetch was installed. libfetch is then installed
in $prefix/lib and its header files are installed in $prefix/include and so
on. The prefix is set with "configure --prefix".

## --protocols

Lists what particular protocols the installed libfetch was built to support. At
the time of writing, this list may include HTTP, HTTPS, FTP, FTPS, FILE,
TELNET, LDAP, DICT and many more. Do not assume any particular order. The
protocols are listed using uppercase and are separated by newlines. There may
be none, one, or several protocols in the list. (Added in 7.13.0)

## --ssl-backends

Lists the SSL backends that were enabled when libfetch was built. It might be
no, one or several names. If more than one name, they appear comma-separated.
(Added in 7.58.0)

## --static-libs

Shows the complete set of libs and other linker options you need in order to
link your application with libfetch statically. (Added in 7.17.1)

## --version

Outputs version information about the installed libfetch.

## --vernum

Outputs version information about the installed libfetch, in numerical mode.
This shows the version number, in hexadecimal, using 8 bits for each part:
major, minor, and patch numbers. This makes libfetch 7.7.4 appear as 070704 and
libfetch 12.13.14 appear as 0c0d0e... Note that the initial zero might be
omitted. (This option was broken in the 7.15.0 release.)

# EXAMPLES

What linker options do I need when I link with libfetch?
~~~
  $ fetch-config --libs
~~~
What compiler options do I need when I compile using libfetch functions?
~~~
  $ fetch-config --cflags
~~~
How do I know if libfetch was built with SSL support?
~~~
  $ fetch-config --feature | grep SSL
~~~
What's the installed libfetch version?
~~~
  $ fetch-config --version
~~~
How do I build a single file with a one-line command?
~~~
  $ `fetch-config --cc --cflags` -o example source.c `fetch-config --libs`
~~~
