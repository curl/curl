---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: curl-config
Section: 1
Source: curl-config
See-also:
  - curl (1)
Added-in: 7.7.2
---

# NAME

curl-config - Get information about a libcurl installation

# SYNOPSIS

**curl-config [options]**

# DESCRIPTION

**curl-config**
displays information about the curl and libcurl installation.

# OPTIONS

## `--ca`

Displays the built-in path to the CA cert bundle this libcurl uses.

## `--cc`

Displays the compiler used to build libcurl.

## `--cflags`

Set of compiler options (CFLAGS) to use when compiling files that use
libcurl. Currently that is only the include path to the curl include files.

## `--checkfor [version]`

Specify the oldest possible libcurl version string you want, and this script
returns 0 if the current installation is new enough or it returns 1 and
outputs a text saying that the current version is not new enough. (Added in
7.15.4)

## `--configure`

Displays the arguments given to configure when building curl.

## `--feature`

Lists what particular main features the installed libcurl was built with. At
the time of writing, this list may include SSL, KRB4 or IPv6. Do not assume
any particular order. The keywords are separated by newlines. There may be
none, one, or several keywords in the list.

## `--help`

Displays the available options.

## `--libs`

Shows the complete set of libs and other linker options you need in order to
link your application with libcurl.

## `--prefix`

This is the prefix used when libcurl was installed. libcurl is then installed
in $prefix/lib and its header files are installed in $prefix/include and so
on. The prefix is set with `configure --prefix`.

## `--protocols`

Lists what particular protocols the installed libcurl was built to support. At
the time of writing, this list may include HTTP, HTTPS, FTP, FTPS, FILE,
TELNET, LDAP, DICT and many more. Do not assume any particular order. The
protocols are listed using uppercase and are separated by newlines. There may
be none, one, or several protocols in the list. (Added in 7.13.0)

## `--ssl-backends`

Lists the SSL backends that were enabled when libcurl was built. It might be
no, one or several names. If more than one name, they appear comma-separated.
(Added in 7.58.0)

## `--static-libs`

Shows the complete set of libs and other linker options you need in order to
link your application with libcurl statically. (Added in 7.17.1)

## `--version`

Outputs version information about the installed libcurl.

## `--vernum`

Outputs version information about the installed libcurl, in numerical mode.
This shows the version number, in hexadecimal, using 8 bits for each part:
major, minor, and patch numbers. This makes libcurl 7.7.4 appear as 070704 and
libcurl 12.13.14 appear as 0c0d0e... Note that the initial zero might be
omitted. (This option was broken in the 7.15.0 release.)

# EXAMPLES

What linker options do I need when I link with libcurl?

    $ curl-config --libs

What compiler options do I need when I compile using libcurl functions?

    $ curl-config --cflags

How do I know if libcurl was built with SSL support?

    $ curl-config --feature | grep SSL

What's the installed libcurl version?

    $ curl-config --version

How do I build a single file with a one-line command?

    $ `curl-config --cc --cflags` -o example source.c `curl-config --libs`
