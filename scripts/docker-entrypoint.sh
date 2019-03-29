#!/bin/sh
#
# Copyright (C) 2019 Olliver Schinagl <oliver@schinagl.nl>
#
# SPDX-License-Identifier: BSD-4-Clause
#
# A beginning user should be able to docker run image bash (or sh) without
# needing to learn about --entrypoint
# https://github.com/docker-library/official-images#consistency

set -eu

# run command if it is not starting with a "-" and is an executable in PATH
if [ "${#}" -gt "0" ] && \
   [ "${1#-}" = "${1}" ] && \
   command -v "${1}"; then
    exec "${@}"
else
    # else default to run command with curl
    exec curl "${@}"
fi
