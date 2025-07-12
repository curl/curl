#!/bin/sh
# Copyright (C) Viktor Szakats
#
# SPDX-License-Identifier: curl

set -eu

cd "$(dirname "${0}")"/../..

git ls-files \
| grep -v -E '(codespell-ignore\.txt|spellcheck\.words|/wcurl|CIPHERS-TLS12\.md|/THANKS)' \
| typos \
    --config '.github/scripts/typos.toml' \
    --file-list -
