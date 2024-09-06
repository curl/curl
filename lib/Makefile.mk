#***************************************************************************
#                                  _   _ ____  _
#  Project                     ___| | | |  _ \| |
#                             / __| | | | |_) | |
#                            | (__| |_| |  _ <| |___
#                             \___|\___/|_| \_\_____|
#
# Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
#
# This software is licensed as described in the file COPYING, which
# you should have received as part of this distribution. The terms
# are also available at https://curl.se/docs/copyright.html.
#
# You may opt to use, copy, modify, merge, publish, distribute and/or sell
# copies of the Software, and permit persons to whom the Software is
# furnished to do so, under the terms of the COPYING file.
#
# This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
# KIND, either express or implied.
#
# SPDX-License-Identifier: curl
#
#***************************************************************************

# Makefile to build curl parts with GCC-like toolchains and optional features.
#
# Usage:   make -f Makefile.mk CFG=-feat1[-feat2][-feat3][...]
# Example: make -f Makefile.mk CFG=-zlib-ssl-libssh2-ipv6
#
# Look for ' ?=' to find accepted customization variables.

# This script is reused by 'src' and 'docs/examples' Makefile.mk scripts.

ifndef PROOT
  PROOT := ..
  LOCAL := 1
endif

### Common

CFLAGS ?=
CPPFLAGS ?=
LDFLAGS ?=
LIBS ?=

CROSSPREFIX ?=

ifeq ($(CC),cc)
  CC := gcc
endif
CC := $(CROSSPREFIX)$(CC)
AR := $(CROSSPREFIX)$(AR)

TRIPLET ?= $(shell $(CC) -dumpmachine)

BIN_EXT :=

ifneq ($(findstring msdos,$(TRIPLET)),)
  # Cross-tools: https://github.com/andrewwutw/build-djgpp
  MSDOS := 1
  BIN_EXT := .exe
else ifneq ($(findstring amigaos,$(TRIPLET)),)
  # Cross-tools: https://github.com/bebbo/amiga-gcc
  AMIGA := 1
endif

CPPFLAGS += -I. -I$(PROOT)/include

### Deprecated settings. For compatibility.

ifdef WATT_ROOT
  WATT_PATH := $(realpath $(WATT_ROOT))
endif

### Optional features

ifneq ($(findstring -debug,$(CFG)),)
  CFLAGS += -g
  CPPFLAGS += -DDEBUGBUILD
else
  CPPFLAGS += -DNDEBUG
endif
ifneq ($(findstring -trackmem,$(CFG)),)
  CPPFLAGS += -DCURLDEBUG
endif
ifneq ($(findstring -map,$(CFG)),)
  MAP := 1
endif

# CPPFLAGS below are only necessary when building libcurl via 'lib' (see
# comments below about exceptions). Always include them anyway to match
# behavior of other build systems.

ifneq ($(findstring -sync,$(CFG)),)
  CPPFLAGS += -DUSE_SYNC_DNS
else ifneq ($(findstring -ares,$(CFG)),)
  LIBCARES_PATH ?= $(PROOT)/../c-ares
  CPPFLAGS += -DUSE_ARES
  CPPFLAGS += -I"$(LIBCARES_PATH)/include"
  LDFLAGS += -L"$(LIBCARES_PATH)/lib"
  LIBS += -lcares
endif

ifneq ($(findstring -rtmp,$(CFG)),)
  LIBRTMP_PATH ?= $(PROOT)/../librtmp
  CPPFLAGS += -DUSE_LIBRTMP
  CPPFLAGS += -I"$(LIBRTMP_PATH)"
  LDFLAGS += -L"$(LIBRTMP_PATH)/librtmp"
  LIBS += -lrtmp
  ZLIB := 1
endif

ifneq ($(findstring -ssh2,$(CFG)),)
  LIBSSH2_PATH ?= $(PROOT)/../libssh2
  CPPFLAGS += -DUSE_LIBSSH2
  CPPFLAGS += -I"$(LIBSSH2_PATH)/include"
  LDFLAGS += -L"$(LIBSSH2_PATH)/lib"
  LIBS += -lssh2
else ifneq ($(findstring -libssh,$(CFG)),)
  LIBSSH_PATH ?= $(PROOT)/../libssh
  CPPFLAGS += -DUSE_LIBSSH
  CPPFLAGS += -I"$(LIBSSH_PATH)/include"
  LDFLAGS += -L"$(LIBSSH_PATH)/lib"
  LIBS += -lssh
else ifneq ($(findstring -wolfssh,$(CFG)),)
  WOLFSSH_PATH ?= $(PROOT)/../wolfssh
  CPPFLAGS += -DUSE_WOLFSSH
  CPPFLAGS += -I"$(WOLFSSH_PATH)/include"
  LDFLAGS += -L"$(WOLFSSH_PATH)/lib"
  LIBS += -lwolfssh
endif

ifneq ($(findstring -ssl,$(CFG)),)
  OPENSSL_PATH ?= $(PROOT)/../openssl
  CPPFLAGS += -DUSE_OPENSSL
  CPPFLAGS += -DCURL_DISABLE_OPENSSL_AUTO_LOAD_CONFIG
  OPENSSL_INCLUDE ?= $(OPENSSL_PATH)/include
  OPENSSL_LIBPATH ?= $(OPENSSL_PATH)/lib
  CPPFLAGS += -I"$(OPENSSL_INCLUDE)"
  LDFLAGS += -L"$(OPENSSL_LIBPATH)"
  OPENSSL_LIBS ?= -lssl -lcrypto
  LIBS += $(OPENSSL_LIBS)

  ifneq ($(findstring -srp,$(CFG)),)
    ifneq ($(wildcard $(OPENSSL_INCLUDE)/openssl/srp.h),)
      # OpenSSL 1.0.1 and later.
      CPPFLAGS += -DHAVE_OPENSSL_SRP -DUSE_TLS_SRP
    endif
  endif
  SSLLIBS += 1
endif
ifneq ($(findstring -wolfssl,$(CFG)),)
  WOLFSSL_PATH ?= $(PROOT)/../wolfssl
  CPPFLAGS += -DUSE_WOLFSSL
  CPPFLAGS += -DSIZEOF_LONG_LONG=8
  CPPFLAGS += -I"$(WOLFSSL_PATH)/include"
  LDFLAGS += -L"$(WOLFSSL_PATH)/lib"
  LIBS += -lwolfssl
  SSLLIBS += 1
endif
ifneq ($(findstring -mbedtls,$(CFG)),)
  MBEDTLS_PATH ?= $(PROOT)/../mbedtls
  CPPFLAGS += -DUSE_MBEDTLS
  CPPFLAGS += -I"$(MBEDTLS_PATH)/include"
  LDFLAGS += -L"$(MBEDTLS_PATH)/lib"
  LIBS += -lmbedtls -lmbedx509 -lmbedcrypto
  SSLLIBS += 1
endif

ifneq ($(findstring -nghttp2,$(CFG)),)
  NGHTTP2_PATH ?= $(PROOT)/../nghttp2
  CPPFLAGS += -DUSE_NGHTTP2
  CPPFLAGS += -I"$(NGHTTP2_PATH)/include"
  LDFLAGS += -L"$(NGHTTP2_PATH)/lib"
  LIBS += -lnghttp2
endif

ifeq ($(findstring -nghttp3,$(CFG))$(findstring -ngtcp2,$(CFG)),-nghttp3-ngtcp2)
  NGHTTP3_PATH ?= $(PROOT)/../nghttp3
  CPPFLAGS += -DUSE_NGHTTP3
  CPPFLAGS += -I"$(NGHTTP3_PATH)/include"
  LDFLAGS += -L"$(NGHTTP3_PATH)/lib"
  LIBS += -lnghttp3

  NGTCP2_PATH ?= $(PROOT)/../ngtcp2
  CPPFLAGS += -DUSE_NGTCP2
  CPPFLAGS += -I"$(NGTCP2_PATH)/include"
  LDFLAGS += -L"$(NGTCP2_PATH)/lib"

  NGTCP2_LIBS ?=
  ifeq ($(NGTCP2_LIBS),)
    ifneq ($(findstring -ssl,$(CFG)),)
      ifneq ($(wildcard $(OPENSSL_INCLUDE)/openssl/aead.h),)
        NGTCP2_LIBS := -lngtcp2_crypto_boringssl
      else  # including libressl
        NGTCP2_LIBS := -lngtcp2_crypto_quictls
      endif
    else ifneq ($(findstring -wolfssl,$(CFG)),)
      NGTCP2_LIBS := -lngtcp2_crypto_wolfssl
    endif
  endif

  LIBS += -lngtcp2 $(NGTCP2_LIBS)
endif

ifneq ($(findstring -zlib,$(CFG))$(ZLIB),)
  ZLIB_PATH ?= $(PROOT)/../zlib
  # These CPPFLAGS are also required when compiling the curl tool via 'src'.
  CPPFLAGS += -DHAVE_LIBZ
  CPPFLAGS += -I"$(ZLIB_PATH)/include"
  LDFLAGS += -L"$(ZLIB_PATH)/lib"
  ZLIB_LIBS ?= -lz
  LIBS += $(ZLIB_LIBS)
  ZLIB := 1
endif
ifneq ($(findstring -zstd,$(CFG)),)
  ZSTD_PATH ?= $(PROOT)/../zstd
  CPPFLAGS += -DHAVE_ZSTD
  CPPFLAGS += -I"$(ZSTD_PATH)/include"
  LDFLAGS += -L"$(ZSTD_PATH)/lib"
  ZSTD_LIBS ?= -lzstd
  LIBS += $(ZSTD_LIBS)
endif
ifneq ($(findstring -brotli,$(CFG)),)
  BROTLI_PATH ?= $(PROOT)/../brotli
  CPPFLAGS += -DHAVE_BROTLI
  CPPFLAGS += -I"$(BROTLI_PATH)/include"
  LDFLAGS += -L"$(BROTLI_PATH)/lib"
  BROTLI_LIBS ?= -lbrotlidec -lbrotlicommon
  LIBS += $(BROTLI_LIBS)
endif
ifneq ($(findstring -gsasl,$(CFG)),)
  LIBGSASL_PATH ?= $(PROOT)/../gsasl
  CPPFLAGS += -DUSE_GSASL
  CPPFLAGS += -I"$(LIBGSASL_PATH)/include"
  LDFLAGS += -L"$(LIBGSASL_PATH)/lib"
  LIBS += -lgsasl
endif

ifneq ($(findstring -idn2,$(CFG)),)
  LIBIDN2_PATH ?= $(PROOT)/../libidn2
  CPPFLAGS += -DHAVE_LIBIDN2 -DHAVE_IDN2_H
  CPPFLAGS += -I"$(LIBIDN2_PATH)/include"
  LDFLAGS += -L"$(LIBIDN2_PATH)/lib"
  LIBS += -lidn2

ifneq ($(findstring -psl,$(CFG)),)
  LIBPSL_PATH ?= $(PROOT)/../libpsl
  CPPFLAGS += -DUSE_LIBPSL
  CPPFLAGS += -I"$(LIBPSL_PATH)/include"
  LDFLAGS += -L"$(LIBPSL_PATH)/lib"
  LIBS += -lpsl
endif
endif

ifneq ($(findstring -ipv6,$(CFG)),)
  CPPFLAGS += -DUSE_IPV6
endif

ifneq ($(findstring -watt,$(CFG))$(MSDOS),)
  WATT_PATH ?= $(PROOT)/../watt
  CPPFLAGS += -I"$(WATT_PATH)/inc"
  LDFLAGS += -L"$(WATT_PATH)/lib"
  LIBS += -lwatt
endif

ifneq ($(findstring 11,$(subst $(subst ,, ),,$(SSLLIBS))),)
  CPPFLAGS += -DCURL_WITH_MULTI_SSL
endif

### Common rules

OBJ_DIR := $(TRIPLET)

ifneq ($(findstring /sh,$(SHELL)),)
DEL   = rm -f $1
COPY  = -cp -afv $1 $2
MKDIR = mkdir -p $1
RMDIR = rm -fr $1
else
DEL   = -del 2>NUL /q /f $(subst /,\,$1)
COPY  = -copy 2>NUL /y $(subst /,\,$1) $(subst /,\,$2)
MKDIR = -md 2>NUL $(subst /,\,$1)
RMDIR = -rd 2>NUL /q /s $(subst /,\,$1)
endif

all: $(TARGETS)

$(OBJ_DIR):
	-$(call MKDIR, $(OBJ_DIR))

$(OBJ_DIR)/%.o: %.c
	$(CC) -W -Wall $(CFLAGS) $(CPPFLAGS) -c $< -o $@

clean:
	@$(call DEL, $(TOCLEAN))
	@$(RMDIR) $(OBJ_DIR)

distclean vclean: clean
	@$(call DEL, $(TARGETS) $(TOVCLEAN))

### Local

ifdef LOCAL

CPPFLAGS += -DBUILDING_LIBCURL

### Sources and targets

# Provides CSOURCES, HHEADERS
include Makefile.inc

vpath %.c vauth vquic vssh vtls

libcurl_a_LIBRARY := libcurl.a

TARGETS := $(libcurl_a_LIBRARY)

libcurl_a_OBJECTS := $(patsubst %.c,$(OBJ_DIR)/%.o,$(notdir $(strip $(CSOURCES))))
libcurl_a_DEPENDENCIES := $(strip $(CSOURCES) $(HHEADERS))

TOCLEAN :=
TOVCLEAN :=

### Rules

$(libcurl_a_LIBRARY): $(libcurl_a_OBJECTS) $(libcurl_a_DEPENDENCIES)
	@$(call DEL, $@)
	$(AR) rcs $@ $(libcurl_a_OBJECTS)

all: $(OBJ_DIR) $(TARGETS)
endif
