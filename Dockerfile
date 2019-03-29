#
# Copyright (C) 2019 Olliver Schinagl <oliver@schinagl.nl>
#
# SPDX-License-Identifier: BSD-4-Clause

# For Alpine, latest is actually the latest stable
# hadolint ignore=DL3007
FROM registry.hub.docker.com/library/alpine:latest AS builder

LABEL Maintainer="Olliver Schinagl <oliver@schinagl.nl>"

WORKDIR /build

# We want the latest stable version from the repo
# hadolint ignore=DL3018
RUN \
    apk add --no-cache \
       autoconf \
       automake \
       build-base \
       curl-dev \
       groff \
       libtool \
    && \
    rm -rf "/var/cache/apk/"*

COPY . "/build"

RUN \
    autoreconf -vif && \
    ./configure \
        --disable-ldap \
        --enable-ipv6 \
        --enable-unix-sockets \
        --prefix=/usr \
        --with-libssh2 \
        --with-nghttp2 \
        --with-pic \
        --with-ssl \
        --without-libidn \
        --without-libidn2 \
    && \
    make && \
    make DESTDIR="/alpine/" install

# For Alpine, latest is actually the latest stable
# hadolint ignore=DL3007
FROM registry.hub.docker.com/library/alpine:latest

RUN \
    apk add --no-cache \
        curl \
    && \
    rm -rf "/var/cache/apk/"* && \
    for curlfile in $(apk info -L curl libcurl); do \
        if [ -f "/${curlfile}" ]; then \
            rm "/${curlfile:?}"; \
        fi \
    done

COPY --from=builder "/alpine/usr/lib/libcurl.so.4.5.0" "/usr/lib/libcurl.so.4.5.0"
COPY --from=builder "/alpine/usr/lib/libcurl.so.4" "/usr/lib/libcurl.so.4"
COPY --from=builder "/alpine/usr/lib/libcurl.so" "/usr/lib/libcurl.so"
COPY --from=builder "/alpine/usr/bin/curl" "/usr/bin/curl"

COPY "scripts/docker-entrypoint.sh" "/docker-entrypoint.sh"

ENTRYPOINT [ "/docker-entrypoint.sh" ]
