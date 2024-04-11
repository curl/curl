FROM stagex/busybox@sha256:2006bf09c974d842ebc62476074f01181c092022b2a1fdfa63b32d6aed5db323 as busybox
FROM stagex/make@sha256:e9aef80a9b2bd7003c7fb040cb875d4cee94eab777de93a798ed000ea5ee5fc1 as make
FROM stagex/musl@sha256:e52da07cf7e2824fcfc7563e5b8792edc296e8ee37dcb59397ad183e742a6dc0 as musl
FROM stagex/perl@sha256:fc4c642ea8aaf6d9f68b2f01ea5073f781e8994ac2c8267e98b4623d5b2ef752 as perl
FROM stagex/binutils@sha256:47c9449f655b43e3da5fb6ab1694a9d0a513bfa36cae88b27008a8d95f4df943 as binutils
FROM stagex/autoconf@sha256:e42cb175aa5739b511d4ab75a6dd24797bcaa957f12082240b875f8ab68c1fa0 as autoconf
FROM stagex/automake@sha256:749940b3c06e7e1f80f667a0870d59a00c86298e865530f6d11c85b1d05fc548 as automake
FROM stagex/pkgconf@sha256:470052019202f89aa8a63cf227364beb2e23e3e5d3e15d413c7df48cdb891aef as pkgconf
FROM stagex/libtool@sha256:40037dd8aba84b58e9c08390043e53cc90b4d6e2f4abfb4978674030f63fe219 as libtool
FROM stagex/file@sha256:1195ad7a437d5a2b2cfe8f5319945111d730baf62838718f5d4aa5b54240d3af as file
FROM stagex/zlib@sha256:d5c4a74d4c0a71fece685ec5e8f8a7d37b14fbbe79d00611585030c6b0542182 as zlib
FROM stagex/m4@sha256:2c8b055ce71cc5452b519b5b0540ce5e0ef9d36fc14164d5609e35dff85d2ce9 as m4
FROM stagex/gcc@sha256:a5c3774cb42719d308f98fc9311fea3a73f638353a7ed81bc9bef39803c8dadd as gcc
FROM stagex/bzip2@sha256:79b9f18b94fe2dd27709ff5960849c7b40482b64ed8a64c6f5c1992e0c08d85a as bzip2
FROM stagex/xz@sha256:8a8843cd206bcf8322f5d1446284e05e7db282a1deeeab02ec7aeaca23a0f858 as xz
FROM stagex/tar@sha256:45d9dd30aa7a447755d5671654b22ae7aabf43048e694f098ade81aba0878959 as tar

FROM scratch as build
ARG VERSION=unknown
COPY --from=musl . /
COPY --from=busybox . /
COPY --from=make . /
COPY --from=perl . /
COPY --from=binutils . /
COPY --from=autoconf . /
COPY --from=automake . /
COPY --from=libtool . /
COPY --from=m4 . /
COPY --from=file . /
COPY --from=zlib . /
COPY --from=gcc . /
COPY --from=bzip2 . /
COPY --from=xz . /
COPY --from=tar . /
ADD . /src
WORKDIR /src
ENV SOURCE_DATE_EPOCH=1
RUN --network=none <<-EOF
    set -eux
    autoreconf -fvi
    ./configure --without-ssl --without-libpsl
    make
    ./maketgz ${VERSION}
    mkdir /rootfs
    mv curl-${VERSION}.* /rootfs
EOF

FROM scratch as package
COPY --from=build /rootfs/. /
