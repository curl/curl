# ***************************************************************************
# *                                  _   _ ____  _
# *  Project                     ___| | | |  _ \| |
# *                             / __| | | | |_) | |
# *                            | (__| |_| |  _ <| |___
# *                             \___|\___/|_| \_\_____|
# *
# * Copyright (C) 1998 - 2012, Daniel Stenberg, <daniel@haxx.se>, et al.
# *
# * This software is licensed as described in the file COPYING, which
# * you should have received as part of this distribution. The terms
# * are also available at http://curl.haxx.se/docs/copyright.html.
# *
# * You may opt to use, copy, modify, merge, publish, distribute and/or sell
# * copies of the Software, and permit persons to whom the Software is
# * furnished to do so, under the terms of the COPYING file.
# *
# * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
# * KIND, either express or implied.
# *
# ***************************************************************************
# awk script which fetches curl version number and copyright string from input
# file and writes them to STDOUT. Here you can get an awk version for Win32:
# http://www.gknw.net/development/prgtools/awk-20100523.zip
#
BEGIN {
  while ((getline < ARGV[1]) > 0) {
    sub("\r", "") # make MSYS gawk work with CRLF header input.
    if (match ($0, /^#define LIBCURL_COPYRIGHT "([^"]+)"$/))
      copyright_string = substr($0, 28, length($0)-28)
    else if (match ($0, /^#define LIBCURL_VERSION "[^"]+"$/))
      version_string = substr($3, 2, length($3)-2)
    else if (match ($0, /^#define LIBCURL_VERSION_MAJOR [0-9]+$/))
      version_major = $3
    else if (match ($0, /^#define LIBCURL_VERSION_MINOR [0-9]+$/))
      version_minor = $3
    else if (match ($0, /^#define LIBCURL_VERSION_PATCH [0-9]+$/))
      version_patch = $3
  }
  print "LIBCURL_VERSION = " version_major "," version_minor "," version_patch
  print "LIBCURL_VERSION_STR = " version_string
  print "LIBCURL_COPYRIGHT_STR = " copyright_string
}

