# Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
#
# SPDX-License-Identifier: curl

# Self-contained build environment to match the release environment.
#
# Build and set the timestamp for the date corresponding to the release
#
#   docker build --build-arg SOURCE_DATE_EPOCH=1711526400 --build-arg UID=$(id -u) --build-arg GID=$(id -g) -t curl/curl .
#
# Then run commands from within the build environment, for example
#
#   docker run --rm -it -u $(id -u):$(id -g) -v $(pwd):/usr/src -w /usr/src curl/curl autoreconf -fi
#   docker run --rm -it -u $(id -u):$(id -g) -v $(pwd):/usr/src -w /usr/src curl/curl ./configure --without-ssl --without-libpsl
#   docker run --rm -it -u $(id -u):$(id -g) -v $(pwd):/usr/src -w /usr/src curl/curl make
#   docker run --rm -it -u $(id -u):$(id -g) -v $(pwd):/usr/src -w /usr/src curl/curl ./scripts/maketgz 8.7.1
#
# or get into a shell in the build environment, for example
#
#   docker run --rm -it -u $(id -u):$(id -g) -v $(pwd):/usr/src -w /usr/src curl/curl bash
#   $ autoreconf -fi
#   $ ./configure --without-ssl --without-libpsl
#   $ make
#   $ ./scripts/maketgz 8.7.1

# To update, get the latest digest e.g. from https://hub.docker.com/_/debian/tags
FROM debian:bookworm-slim@sha256:6ac2c08566499cc2415926653cf2ed7c3aedac445675a013cc09469c9e118fdd

RUN apt-get update -qq && apt-get install -qq -y --no-install-recommends \
    build-essential make autoconf automake libtool git perl zip zlib1g-dev gawk && \
    rm -rf /var/lib/apt/lists/*

ARG UID=1000 GID=1000

RUN groupadd --gid $UID dev && \
    useradd --uid $UID --gid dev --shell /bin/bash --create-home dev

USER dev:dev

ARG SOURCE_DATE_EPOCH
ENV SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH:-1}
