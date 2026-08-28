#!/usr/bin/env bash
# Copyright (C) Viktor Szakats
#
# SPDX-License-Identifier: curl

# Compare git repo files with tarball files and report a mismatch
# after excluding exceptions.

set -eu

gitonly=".git*
^.circleci/*
^.dir-locals.el
^.mailmap
^appveyor.*
^GIT-INFO.md
^README.md
^renovate.json
^REUSE.toml
^SECURITY.md
^LICENSES/*
^docs/examples/adddocsref.pl
^docs/tests/CI.md
^docs/THANKS-filter
^projects/Windows/*
^scripts/contributors.sh
^scripts/contrithanks.sh
^scripts/delta
^scripts/installcheck.sh
^scripts/release-notes.pl
^scripts/singleuse.pl"

taronly="^Makefile.in$
/Makefile.in$
^aclocal.m4$
^compile$
^configure$
^config.guess$
^config.sub$
^depcomp$
^docs/RELEASE-TOOLS.md$
^docs/libcurl/libcurl-symbols.md$
^install-sh$
^lib/curl_config.h.in$
^ltmain.sh$
^m4/libtool.m4$
^m4/lt*.m4$
^missing$
^src/tool_hugehelp.c$"

tarfiles="$(mktemp)"
gitfiles="$(mktemp)"

tar -tf "$1" \
  | sed -E 's|^[^/]+/||g' \
  | grep -v -E '(/|^)$' \
  | sort > "${tarfiles}"

git -C "${2:-.}" ls-files \
  | grep -v -E "($(printf '%s' "${gitonly}" | tr $'\n' '|' | sed -e 's|\.|\\.|g' -e 's|\*|.+|g'))$" \
  | sort > "${gitfiles}"

dif="$(diff -u "${tarfiles}" "${gitfiles}" | tail -n +3 || true)"

rm -rf "${tarfiles:?}" "${gitfiles:?}"

echo 'Only in tarball:'
echo "${dif}" | grep '^-' || true
echo

exitcode=0

echo 'Unexpected in tarball:'
if echo "${dif}" | grep '^-' | sed 's|^-||g' \
  | grep -v -E "($(printf '%s' "${taronly}" | tr $'\n' '|' | sed -e 's|\.|\\.|g' -e 's|\*|.+|g'))$"; then
  exitcode=1
fi

echo 'Missing from tarball:'
if echo "${dif}" | grep '^+'; then
  exitcode=1
fi

exit "${exitcode}"
