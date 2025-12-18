#!/bin/sh
# Copyright (C) Viktor Szakats
#
# SPDX-License-Identifier: curl

# Required: yq

set -eu

export SHELLCHECK_OPTS='--exclude=1090,1091,2086,2153 --enable=avoid-nullary-conditions,deprecate-which'

# GHA
git ls-files '.github/workflows/*.yml' | while read -r f; do
  echo "Verifying ${f}..."
  {
    echo '#!/usr/bin/env bash'
    echo 'set -eu'
    yq eval '.. | select(has("run") and (.run | type == "!!str")) | .run + "\ntrue\n"' "${f}"
  } | sed -E 's|\$\{\{ .+ \}\}|GHA_EXPRESSION|g' | shellcheck -
done

# Circle CI
git ls-files '.circleci/*.yml' | while read -r f; do
  echo "Verifying ${f}..."
  {
    echo '#!/usr/bin/env bash'
    echo 'set -eu'
    yq eval '.. | select(has("command") and (.command | type == "!!str")) | .command + "\ntrue\n"' "${f}"
  } | shellcheck -
done
