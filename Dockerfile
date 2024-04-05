# Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
#
# SPDX-License-Identifier: curl

# Self-contained build environment to match the release environment.
#
# Build with
#
#   docker build -t curl/curl .
#
# Then run commands from within the build environment, for example
#
#   docker run --rm -v $(pwd):/usr/src -w /usr/src curl/curl autoreconf -fi
#   docker run --rm -v $(pwd):/usr/src -w /usr/src curl/curl ./configure --without-ssl --without-libpsl
#   docker run --rm -v $(pwd):/usr/src -w /usr/src curl/curl make
#   docker run --rm -v $(pwd):/usr/src -w /usr/src curl/curl ./maketgz 8.7.1

FROM debian:bookworm-slim@sha256:993f5593466f84c9200e3e877ab5902dfc0e4a792f291c25c365dbe89833411f
# autoconf 2.71
# automake 1.16.5
# libtoolize 2.4.7
# make 4.3
# perl 5.36.0
# git 2.39.2

RUN apt-get update -qq && apt-get install -qq -y --no-install-recommends \
    build-essential make autoconf automake libtool git perl zip zlib1g-dev gawk && \
    rm -rf /var/lib/apt/lists/*

# >>> from datetime import datetime
# >>> int(datetime(2024, 3, 27, 9).timestamp())
# 1711526400
ENV LC_ALL=C TZ=UTC SOURCE_DATE_EPOCH=1711526400

RUN git config --global --add safe.directory /usr/src
