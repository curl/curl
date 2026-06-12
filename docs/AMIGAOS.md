<!--
Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.

SPDX-License-Identifier: curl
-->

# curl for AmigaOS

This document describes the AmigaOS 3.x binary archive for curl 8.18.0-DEV
and libcurl 8.18.0-DEV.

```text
curl 8.18.0-DEV
-------------------------------------
libcurl/8.18.0-DEV AmiSSL/5.x OpenSSL/3.6.0 zlib/1.3.1
Protocols: dict file ftp ftps gopher gophers http https imap imaps
           ipfs ipns mqtt pop3 pop3s rtsp smb smbs smtp smtps telnet
           tftp ws wss
Features:  alt-svc HSTS HTTPS-proxy libz NTLM SSL TLS-SRP threadsafe
```

curl is a command line tool for transferring data specified with URL syntax.
The archive also includes libcurl, which allows Amiga developers to link curl
functionality directly into their own applications.

The AmigaOS archive is tested on multiple CPU targets and SSL workloads.

## System requirements

- AmiSSL v5.0 or newer (mandatory)
- AmigaOS 3.x (3.2.2.1 tested, works on 3.0-3.1)
- 68000, 68020, 68040, or 68060 CPU (no FPU required)
- Minimum stack: 32768 bytes
  - AmigaOS 3.1.4 and newer auto-select the correct stack
  - Older versions: set it manually with `STACK 32768`
- Roadshow TCP tested
- WinUAE TCP tested
- Real hardware and emulation tested

## What's new in 8.18.0 (AmigaOS release)

- Increased the default stack size from 16384 to 32768. This fixes crashes
  during TLS handshakes, certificate validation, compressed downloads, and
  large HTTPS transfers.
- Retested all supported CPU targets: 68000, 68020, 68040, and 68060. All
  binaries now pass TLS tests reliably.
- Updated build system:
  - GCC 15.2 m68k-amigaos toolchain
  - clib2 runtime
  - soft-float ABI
  - dynamic AmiSSL linking
  - `-O0` due to current GCC 15 m68k optimization issues
- Updated protocol support, matching upstream curl 8.18.0 except for protocols
  requiring unsupported libraries, such as HTTP/2, HTTP/3, SSH, LDAP, IDN,
  PSL, Brotli, and Zstd.

## Files included

| File | Description |
| ---- | ----------- |
| `curl` | 68000 binary |
| `curl.020` | 68020 binary |
| `curl.040` | 68040 binary |
| `curl.060` | 68060 binary |
| `libcurl.a` | static library (68000) |
| `libcurl.a.020` | static library (68020+) |
| `libcurl.a.040` | static library (68040) |
| `libcurl.a.060` | static library (68060) |

Developers should use the matching libcurl library for their target CPU when
building Amiga applications.

## Developer information

Used compiler:

```text
m68k-amigaos-gcc (GCC) 15.2.0
```

Example autotools configuration:

```sh
./buildconf &&
PKG_CONFIG=true ./configure \
  --host=m68k-amigaos \
  CC=m68k-amigaos-gcc \
  --disable-shared \
  --disable-ipv6 \
  --prefix=/opt/amiga15 \
  --disable-netrc \
  --without-libpsl \
  --with-amissl \
  --with-zlib \
  --disable-threaded-resolver \
  CFLAGS="-m68000 -O0 -msoft-float -mcrt=clib2" \
  LIBS="-lnet -lm -lc -lz -lunix -latomic"
```

Source code for this AmigaOS port is available at:

<https://github.com/boingball/curl>

## Release notes

### curl 8.18.0 - 2025-11-18

- Increased stack cookie to 32768 for TLS stability
- Updated to GCC 15.2 toolchain
- Added CPU-specific libcurl libraries
- Reviewed minor AmigaOS fixes upstream

### curl 8.11.2 - 2024-11-26

- Added stack cookie 16384
- Improved TLS robustness

### curl 8.11.1 - 2024-11-24

- Initial modern port of curl 8.11 for AmigaOS 3.x

## Distribution

Study the `COPYING` file for distribution terms.
