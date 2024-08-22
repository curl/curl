#!/bin/sh
# Copyright (C) Viktor Szakats
#
# SPDX-License-Identifier: curl

set -eu

# shellcheck disable=SC2046
yamllint \
  --format parsable \
  --strict \
  --config-data "$(dirname "$0")/yamlcheck.yaml" \
  $(git ls-files '*.yaml' '*.yml')
