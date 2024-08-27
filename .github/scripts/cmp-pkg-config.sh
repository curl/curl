#!/usr/bin/env bash
# Copyright (C) Viktor Szakats
#
# SPDX-License-Identifier: curl

# Sort list of libs, libpaths, cflags found in libcurl.pc and curl-config files.

sort_lists() {
  prevline=''
  section=''
  while IFS= read -r l; do
    if [[ "${prevline}" =~ (--cc|--configure) ]]; then  # curl-config
      echo "<IGNORED>"
    else
      # libcurl.pc
      if [[ "${l}" =~ ^(Requires|Libs|Cflags)(\.private)?:(.+)$ ]]; then
        val="$(printf '%s' "${BASH_REMATCH[3]}" | tr ', ' '\n' | sort | tr '\n' ' ')"
        l="${BASH_REMATCH[1]}${BASH_REMATCH[2]}:${val}"
      # curl-config
      elif [[ "${section}" =~ (--libs|--static-libs) && "${l}" =~ ^( *echo\ \")(.+)(\")$ ]]; then
        val="$(printf '%s' "${BASH_REMATCH[2]}" | tr ' ' '\n' | sort | tr '\n' ' ')"
        l="${BASH_REMATCH[1]}${val}${BASH_REMATCH[3]}"
        section=''
      fi
      echo "${l}"
    fi
    # curl-config
    prevline="${l}"
    if [[ "${l}" =~ --[a-z-]+\) ]]; then
      section="${BASH_REMATCH[0]}"
    fi
  done < "$1"
}

am=$(mktemp -t autotools); sort_lists "$1" > "${am}"
cm=$(mktemp -t cmake)    ; sort_lists "$2" > "${cm}"
diff -u "${am}" "${cm}"
res="$?"
rm -r -f "${am}" "${cm}"

exit "${res}"
