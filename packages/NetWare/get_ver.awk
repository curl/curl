# ***************************************************************************
# *                                  _   _ ____  _
# *  Project                     ___| | | |  _ \| |
# *                             / __| | | | |_) | |
# *                            | (__| |_| |  _ <| |___
# *                             \___|\___/|_| \_\_____|
# *
# * Copyright (C) 1998 - 2004, Daniel Stenberg, <daniel@haxx.se>, et al.
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
# * $Id$
# ***************************************************************************
# fetch libcurl version number from input file and write them to STDOUT
BEGIN {
  while ((getline < ARGV[1]) > 0) {
    if (match ($0, /^#define LIBCURL_VERSION "[^"]+"/)) {
      libcurl_ver_str = substr($3, 2, length($3)-2);
    }
    else if (match ($0, /^#define LIBCURL_VERSION_MAJOR [^"]+/)) {
      libcurl_ver_major = substr($3, 1, length($3));
    }
    else if (match ($0, /^#define LIBCURL_VERSION_MINOR [^"]+/)) {
      libcurl_ver_minor = substr($3, 1, length($3));
    }
    else if (match ($0, /^#define LIBCURL_VERSION_PATCH [^"]+/)) {
      libcurl_ver_patch = substr($3, 1, length($3));
    }
  }
  libcurl_ver = libcurl_ver_major "," libcurl_ver_minor "," libcurl_ver_patch;

  print "LIBCURL_VERSION = " libcurl_ver "";
  print "LIBCURL_VERSION_STR = " libcurl_ver_str "";

}
