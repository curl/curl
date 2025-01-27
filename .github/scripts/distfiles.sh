#!/usr/bin/env bash
# Copyright (C) Viktor Szakats
#
# SPDX-License-Identifier: curl

# Compare git repo files with tarball files and report a mismatch
# after excluding exceptions.

set -eu

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
^tests/CI.md"

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

echo 'Missing from tarball:'
if echo "${dif}" | grep '^+'; then
  exit 1
fi
