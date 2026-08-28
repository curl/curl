#!/bin/bash
# Copyright (C) 2026 Dan Fandrich
#
# SPDX-License-Identifier: curl

# Look for invalid patterns in labeler config.
# This is highly sensitive to the format of the labeler.yml file.
# It will also fail if patterns are added containing special shell characters
# like "$" or "|".
grep -E '^ {14}[^-].*\\$' .github/labeler.yml | \
  sed -E -e '/^[[:space:]]*#/d' -e 's/,?\\$//' | \
  xargs -I{} /bin/bash -c 'shopt -s globstar dotglob; ls -d {}' >/dev/null
