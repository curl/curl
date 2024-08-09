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
Makefile.in"

gitonly=".git*
^.*
^appveyor.*
^buildconf
^GIT-INFO.md
^README.md
^renovate.json
^REUSE.toml
^SECURITY.md
^LICENSES/*
^docs/examples/adddocsref.pl
^docs/THANKS-filter
^projects/Windows/*
^scripts/ciconfig.pl
^scripts/cijobs.pl
^scripts/contributors.sh
^scripts/contrithanks.sh
^scripts/delta
^scripts/installcheck.sh
^scripts/release-notes.pl
^scripts/singleuse.pl
^src/tool_hugehelp.c.cvs
^tests/CI.md"

tar -tf "$1" \
  | sed -E 's|^[^/]+/||g' \
  | grep -v -E "($(printf '%s' "${taronly}" | tr $'\n' '|' | sed -e 's|\.|\\.|g' -e 's|\*|.+|g'))$" \
  | sort > "${tarfiles}"

git ls-files \
  | grep -v -E "($(printf '%s' "${gitonly}" | tr $'\n' '|' | sed -e 's|\.|\\.|g' -e 's|\*|.+|g'))$" \
  | sort > "${gitfiles}"

dif="$(diff -u "${tarfiles}" "${gitfiles}" | tail -n +3 || true)"

echo 'Only in tarball:'
echo "${dif}" | grep '^-'
echo

echo 'Missing from tarball:'
echo "${dif}" | grep '^+'
res=$?

rm -rf "${tarfiles:?}" "${gitfiles:?}"

exit "$res"
