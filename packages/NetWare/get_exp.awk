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
# * are also available at https://curl.haxx.se/docs/copyright.html.
# *
# * You may opt to use, copy, modify, merge, publish, distribute and/or sell
# * copies of the Software, and permit persons to whom the Software is
# * furnished to do so, under the terms of the COPYING file.
# *
# * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
# * KIND, either express or implied.
# *
# ***************************************************************************
# awk script which fetches curl function symbols from public header input
# files and write them to STDOUT. Here you can get an awk version for Win32:
# http://www.gknw.net/development/prgtools/awk-20100523.zip
#
BEGIN {
  add_symbol("curl_strequal")
  add_symbol("curl_strnequal")
}

function add_symbol(sym_name) {
  sub(" ", "", sym_name)
  exports[++idx] = sym_name
}


/^CURL_EXTERN .* [*]?curl_.*[(]/ {
  sub("[(].*", "")
  sub("^.* ", "")
  sub("^[*]", "")
  add_symbol($0)
}

END {
  printf("Added %d symbols to export list.\n", idx) > "/dev/stderr"
  # sort symbols with shell sort
  increment = int(idx / 2)
  while (increment > 0) {
    for (i = increment+1; i <= idx; i++) {
      j = i
      temp = exports[i]
      while ((j >= increment+1) && (exports[j-increment] > temp)) {
        exports[j] = exports[j-increment]
        j -= increment
      }
      exports[j] = temp
    }
    if (increment == 2)
      increment = 1
    else
      increment = int(increment*5/11)
  }
  # print the array
  if (EXPPREFIX) {
    printf(" (%s)\n", EXPPREFIX)
  }
  while (x < idx - 1) {
    printf(" %s,\n", exports[++x])
  }
  printf(" %s\n", exports[++x])
}
