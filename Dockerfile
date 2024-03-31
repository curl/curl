# Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
#
# SPDX-License-Identifier: curl

FROM debian:bookworm-slim@sha256:993f5593466f84c9200e3e877ab5902dfc0e4a792f291c25c365dbe89833411f

RUN apt-get update -qq && apt-get install -qq -y --no-install-recommends \
    build-essential make autoconf automake libtool git perl zip && \
    rm -rf /var/lib/apt/lists/*
