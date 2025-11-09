#!/bin/sh
# Copyright (C) Viktor Szakats
#
# SPDX-License-Identifier: curl

set -eu

cd "$(dirname "${0}")"/../..

git ls-files -z '*.yaml' '*.yml' | xargs -0 -r \
yamllint \
  --format standard \
  --strict \
  --config-data .github/scripts/yamlcheck.yaml \
  --
