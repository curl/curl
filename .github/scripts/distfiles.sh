#!/usr/bin/env bash
# Copyright (C) Viktor Szakats
#
# SPDX-License-Identifier: curl

# Compare git repo files with tarball files and report a mismatch
# after excluding exceptions.

set -eu

tarfiles="$(mktemp)"
gitfiles="$(mktemp)"

taronly="/
^
Makefile\.in
^aclocal.m4
^compile
^configure
^config\..+
^depcomp
^install-sh
^ltmain\.sh
^missing
^docs/libcurl/libcurl-symbols\.md
^docs/RELEASE-TOOLS\.md
^docs/tarball-commit\.txt
^lib/curl_config\.h\.in
^m4/libtool\.m4
^m4/lt.+\.m4
^src/(tool_ca_embed|tool_hugehelp)\.c"

gitonly="\.git.+
^\..+
^appveyor\..+
^buildconf
^renovate\.json
^REUSE\.toml
^(GIT-INFO|README|SECURITY)\.md
^LICENSES/.+
^docs/examples/adddocsref\.pl
^docs/THANKS-filter
^projects/Windows/.+
^scripts/(ciconfig|cijobs|cmp-config|release-notes|singleuse)\.pl
^scripts/(contributors|contrithanks|installcheck)\.sh
^scripts/delta
^src/tool_hugehelp\.c\.cvs
^tests/CI\.md"

tar -tf "$1" \
  | sed -E 's|^[^/]+/||g' \
  | grep -v -E "($(printf '%s' "${taronly}" | tr $'\n' '|'))$" \
  | sort > "${tarfiles}"

git ls-files \
  | grep -v -E "($(printf '%s' "${gitonly}" | tr $'\n' '|'))$" \
  | sort > "${gitfiles}"

diff -u "${tarfiles}" "${gitfiles}"
res=$?

rm -rf "${tarfiles:?}" "${gitfiles:?}"

exit "$res"
