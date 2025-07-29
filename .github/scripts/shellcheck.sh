#!/bin/sh
# Copyright (C) Viktor Szakats
#
# SPDX-License-Identifier: curl

# shellcheck disable=SC2046
shellcheck --exclude=1091 \
  --enable=avoid-nullary-conditions,deprecate-which \
  $(grep -l -E '^#!(/usr/bin/env bash|/bin/sh|/bin/bash)' $(git ls-files))
