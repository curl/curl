#!/bin/sh
# Copyright (C) Viktor Szakats
#
# SPDX-License-Identifier: curl

set -eu

cd "$(dirname "${0}")"/../..

# shellcheck disable=SC2046
codespell \
  --skip '.github/scripts/pyspelling.words' \
  --skip '.github/scripts/typos.toml' \
  --skip 'docs/THANKS' \
  --skip 'packages/*' \
  --skip 'scripts/wcurl' \
  --ignore-regex '.*spellchecker:disable-line' \
  --ignore-words '.github/scripts/codespell-ignore.words' \
  $(git ls-files)
