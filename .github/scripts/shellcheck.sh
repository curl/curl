#!/bin/sh
# Copyright (C) Viktor Szakats
#
# SPDX-License-Identifier: curl

set -eu

cd "$(dirname "${0}")"/../..

git grep -z -l -E '^#!(/usr/bin/env bash|/bin/sh|/bin/bash)' | xargs -0 -r \
shellcheck --exclude=1091,2248 \
  --enable=avoid-nullary-conditions,deprecate-which \
  --
