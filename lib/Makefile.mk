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
# Usage:   [mingw32-]make -f Makefile.mk CFG=-feat1[-feat2][-feat3][...]
# Example: [mingw32-]make -f Makefile.mk CFG=-zlib-ssl-libssh2-ipv6
#
# Look for ' ?=' to find all accepted customization variables.

# This script is reused by 'src' and 'docs/examples' Makefile.mk scripts.

ifndef PROOT
  PROOT := ..
  LOCAL := 1
endif

### Common

CFLAGS ?=
CPPFLAGS ?=
RCFLAGS ?=
LDFLAGS ?=
CURL_LDFLAGS_BIN ?=
CURL_LDFLAGS_LIB ?=
LIBS ?=

CROSSPREFIX ?=

ifeq ($(CC),cc)
  CC := gcc
endif
CC := $(CROSSPREFIX)$(CC)
AR := $(CROSSPREFIX)$(AR)
RC ?= $(CROSSPREFIX)windres

# For compatibility
ARCH ?=
ifeq ($(ARCH),w64)
  TRIPLET := x86_64-w64-mingw32
  CFLAGS  += -m64
  LDFLAGS += -m64
  RCFLAGS += --target=pe-x86-64
else ifdef ARCH
  TRIPLET := i686-w64-mingw32
  CFLAGS  += -m32
  LDFLAGS += -m32
  RCFLAGS += --target=pe-i386
else
  TRIPLET ?= $(shell $(CC) -dumpmachine)
endif

BIN_EXT := .exe

ifneq ($(findstring -w,$(TRIPLET)),)
  WIN32 := 1
else ifneq ($(findstring msdos,$(TRIPLET)),)
  # Cross-tools: https://github.com/andrewwutw/build-djgpp
  MSDOS := 1
else ifneq ($(findstring amigaos,$(TRIPLET)),)
  # Cross-tools: https://github.com/bebbo/amiga-gcc
  AMIGA := 1
endif

CPPFLAGS += -I. -I$(PROOT)/include
RCFLAGS  += -I$(PROOT)/include

ifndef WIN32
  DYN :=
endif

ifdef AMIGA
  BIN_EXT :=
endif

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

ifdef WIN32
  ifneq ($(findstring -unicode,$(CFG)),)
    CPPFLAGS += -DUNICODE -D_UNICODE
    CURL_LDFLAGS_BIN += -municode
  endif
endif

# CPPFLAGS below are only necessary when building libcurl via 'lib' (see
# comments below about exceptions). Always include them anyway to match
# behavior of other build systems.

# Linker options to exclude for shared mode executables.
_LDFLAGS :=
_LIBS :=

ifneq ($(findstring -sync,$(CFG)),)
  CPPFLAGS += -DUSE_SYNC_DNS
else ifneq ($(findstring -ares,$(CFG)),)
  LIBCARES_PATH ?= $(PROOT)/../c-ares
  CPPFLAGS += -DUSE_ARES
  CPPFLAGS += -I"$(LIBCARES_PATH)/include"
  _LDFLAGS += -L"$(LIBCARES_PATH)/lib"
  _LIBS += -lcares
endif

ifneq ($(findstring -rtmp,$(CFG)),)
  LIBRTMP_PATH ?= $(PROOT)/../librtmp
  CPPFLAGS += -DUSE_LIBRTMP
  CPPFLAGS += -I"$(LIBRTMP_PATH)"
  _LDFLAGS += -L"$(LIBRTMP_PATH)/librtmp"
  _LIBS += -lrtmp -lwinmm
  ZLIB := 1
endif

ifneq ($(findstring -ssh2,$(CFG)),)
  LIBSSH2_PATH ?= $(PROOT)/../libssh2
  CPPFLAGS += -DUSE_LIBSSH2
  CPPFLAGS += -I"$(LIBSSH2_PATH)/include"
  _LDFLAGS += -L"$(LIBSSH2_PATH)/lib"
  ifdef WIN32
    _LDFLAGS += -L"$(LIBSSH2_PATH)/win32"
  endif
  _LIBS += -lssh2
else ifneq ($(findstring -libssh,$(CFG)),)
  LIBSSH_PATH ?= $(PROOT)/../libssh
  CPPFLAGS += -DUSE_LIBSSH
  CPPFLAGS += -I"$(LIBSSH_PATH)/include"
  _LDFLAGS += -L"$(LIBSSH_PATH)/lib"
  _LIBS += -lssh
else ifneq ($(findstring -wolfssh,$(CFG)),)
  WOLFSSH_PATH ?= $(PROOT)/../wolfssh
  CPPFLAGS += -DUSE_WOLFSSH
  CPPFLAGS += -I"$(WOLFSSH_PATH)/include"
  _LDFLAGS += -L"$(WOLFSSH_PATH)/lib"
  _LIBS += -lwolfssh
endif

ifneq ($(findstring -ssl,$(CFG)),)
  OPENSSL_PATH ?= $(PROOT)/../openssl
  CPPFLAGS += -DUSE_OPENSSL
  CPPFLAGS += -DCURL_DISABLE_OPENSSL_AUTO_LOAD_CONFIG
  OPENSSL_INCLUDE ?= $(OPENSSL_PATH)/include
  OPENSSL_LIBPATH ?= $(OPENSSL_PATH)/lib
  CPPFLAGS += -I"$(OPENSSL_INCLUDE)"
  _LDFLAGS += -L"$(OPENSSL_LIBPATH)"
  OPENSSL_LIBS ?= -lssl -lcrypto
  _LIBS += $(OPENSSL_LIBS)

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
  _LDFLAGS += -L"$(WOLFSSL_PATH)/lib"
  _LIBS += -lwolfssl
  SSLLIBS += 1
endif
ifneq ($(findstring -mbedtls,$(CFG)),)
  MBEDTLS_PATH ?= $(PROOT)/../mbedtls
  CPPFLAGS += -DUSE_MBEDTLS
  CPPFLAGS += -I"$(MBEDTLS_PATH)/include"
  _LDFLAGS += -L"$(MBEDTLS_PATH)/lib"
  _LIBS += -lmbedtls -lmbedx509 -lmbedcrypto
  SSLLIBS += 1
endif
ifneq ($(findstring -schannel,$(CFG)),)
  CPPFLAGS += -DUSE_SCHANNEL
  SSLLIBS += 1
endif

ifneq ($(findstring -nghttp2,$(CFG)),)
  NGHTTP2_PATH ?= $(PROOT)/../nghttp2
  CPPFLAGS += -DUSE_NGHTTP2
  CPPFLAGS += -I"$(NGHTTP2_PATH)/include"
  _LDFLAGS += -L"$(NGHTTP2_PATH)/lib"
  _LIBS += -lnghttp2
endif

ifeq ($(findstring -nghttp3,$(CFG))$(findstring -ngtcp2,$(CFG)),-nghttp3-ngtcp2)
  NGHTTP3_PATH ?= $(PROOT)/../nghttp3
  CPPFLAGS += -DUSE_NGHTTP3
  CPPFLAGS += -I"$(NGHTTP3_PATH)/include"
  _LDFLAGS += -L"$(NGHTTP3_PATH)/lib"
  _LIBS += -lnghttp3

  NGTCP2_PATH ?= $(PROOT)/../ngtcp2
  CPPFLAGS += -DUSE_NGTCP2
  CPPFLAGS += -I"$(NGTCP2_PATH)/include"
  _LDFLAGS += -L"$(NGTCP2_PATH)/lib"

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

  _LIBS += -lngtcp2 $(NGTCP2_LIBS)
endif

ifneq ($(findstring -zlib,$(CFG))$(ZLIB),)
  ZLIB_PATH ?= $(PROOT)/../zlib
  # These CPPFLAGS are also required when compiling the curl tool via 'src'.
  CPPFLAGS += -DHAVE_LIBZ
  CPPFLAGS += -I"$(ZLIB_PATH)/include"
  _LDFLAGS += -L"$(ZLIB_PATH)/lib"
  ZLIB_LIBS ?= -lz
  _LIBS += $(ZLIB_LIBS)
  ZLIB := 1
endif
ifneq ($(findstring -zstd,$(CFG)),)
  ZSTD_PATH ?= $(PROOT)/../zstd
  CPPFLAGS += -DHAVE_ZSTD
  CPPFLAGS += -I"$(ZSTD_PATH)/include"
  _LDFLAGS += -L"$(ZSTD_PATH)/lib"
  ZSTD_LIBS ?= -lzstd
  _LIBS += $(ZSTD_LIBS)
endif
ifneq ($(findstring -brotli,$(CFG)),)
  BROTLI_PATH ?= $(PROOT)/../brotli
  CPPFLAGS += -DHAVE_BROTLI
  CPPFLAGS += -I"$(BROTLI_PATH)/include"
  _LDFLAGS += -L"$(BROTLI_PATH)/lib"
  BROTLI_LIBS ?= -lbrotlidec -lbrotlicommon
  _LIBS += $(BROTLI_LIBS)
endif
ifneq ($(findstring -gsasl,$(CFG)),)
  LIBGSASL_PATH ?= $(PROOT)/../gsasl
  CPPFLAGS += -DUSE_GSASL
  CPPFLAGS += -I"$(LIBGSASL_PATH)/include"
  _LDFLAGS += -L"$(LIBGSASL_PATH)/lib"
  _LIBS += -lgsasl
endif

ifneq ($(findstring -idn2,$(CFG)),)
  LIBIDN2_PATH ?= $(PROOT)/../libidn2
  CPPFLAGS += -DUSE_LIBIDN2
  CPPFLAGS += -I"$(LIBIDN2_PATH)/include"
  _LDFLAGS += -L"$(LIBIDN2_PATH)/lib"
  _LIBS += -lidn2

ifneq ($(findstring -psl,$(CFG)),)
  LIBPSL_PATH ?= $(PROOT)/../libpsl
  CPPFLAGS += -DUSE_LIBPSL
  CPPFLAGS += -I"$(LIBPSL_PATH)/include"
  _LDFLAGS += -L"$(LIBPSL_PATH)/lib"
  _LIBS += -lpsl
endif
else ifneq ($(findstring -winidn,$(CFG)),)
  CPPFLAGS += -DUSE_WIN32_IDN
  _LIBS += -lnormaliz
endif

ifneq ($(findstring -sspi,$(CFG)),)
  ifdef WIN32
    CPPFLAGS += -DUSE_WINDOWS_SSPI
  endif
endif
ifneq ($(findstring -ipv6,$(CFG)),)
  CPPFLAGS += -DENABLE_IPV6
endif

ifneq ($(findstring -watt,$(CFG))$(MSDOS),)
  WATT_PATH ?= $(PROOT)/../watt
  CPPFLAGS += -I"$(WATT_PATH)/inc"
  _LDFLAGS += -L"$(WATT_PATH)/lib"
  _LIBS += -lwatt
endif

ifdef WIN32
  ifeq ($(findstring -lldap,$(LIBS)),)
    _LIBS += -lwldap32
  endif
  _LIBS += -lws2_32 -lcrypt32 -lbcrypt
endif

ifneq ($(findstring 11,$(subst $(subst ,, ),,$(SSLLIBS))),)
  CPPFLAGS += -DCURL_WITH_MULTI_SSL
endif

ifndef DYN
  LDFLAGS += $(_LDFLAGS)
  LIBS += $(_LIBS)
endif

### Common rules

OBJ_DIR := $(TRIPLET)

ifneq ($(findstring /sh,$(SHELL)),)
DEL   = rm -f $1
COPY  = -cp -afv $1 $2
MKDIR = mkdir -p $1
RMDIR = rm -fr $1
WHICH = $(SHELL) -c "command -v $1"
else
DEL   = -del 2>NUL /q /f $(subst /,\,$1)
COPY  = -copy 2>NUL /y $(subst /,\,$1) $(subst /,\,$2)
MKDIR = -md 2>NUL $(subst /,\,$1)
RMDIR = -rd 2>NUL /q /s $(subst /,\,$1)
WHICH = where $1
endif

all: $(TARGETS)

$(OBJ_DIR):
	-$(call MKDIR, $(OBJ_DIR))

$(OBJ_DIR)/%.o: %.c
	$(CC) -W -Wall $(CFLAGS) $(CPPFLAGS) -c $< -o $@

$(OBJ_DIR)/%.res: %.rc
	$(RC) -O coff $(RCFLAGS) -i $< -o $@

clean:
	@$(call DEL, $(TOCLEAN))
	@$(RMDIR) $(OBJ_DIR)

distclean vclean: clean
	@$(call DEL, $(TARGETS) $(TOVCLEAN))

### Local

ifdef LOCAL

CPPFLAGS += -DBUILDING_LIBCURL

### Sources and targets

# Provides CSOURCES, HHEADERS, LIB_RCFILES
include Makefile.inc

vpath %.c vauth vquic vssh vtls

libcurl_a_LIBRARY := libcurl.a
ifdef WIN32
CURL_DLL_SUFFIX ?=
libcurl_dll_LIBRARY := libcurl$(CURL_DLL_SUFFIX).dll
libcurl_dll_a_LIBRARY := libcurl.dll.a
ifdef MAP
libcurl_map_LIBRARY := libcurl$(CURL_DLL_SUFFIX).map
CURL_LDFLAGS_LIB += -Wl,-Map,$(libcurl_map_LIBRARY)
endif
endif

TARGETS := $(libcurl_a_LIBRARY) $(libcurl_dll_LIBRARY)

libcurl_a_OBJECTS := $(patsubst %.c,$(OBJ_DIR)/%.o,$(notdir $(strip $(CSOURCES))))
libcurl_a_DEPENDENCIES := $(strip $(CSOURCES) $(HHEADERS))
ifdef WIN32
libcurl_dll_OBJECTS := $(libcurl_a_OBJECTS)
libcurl_dll_OBJECTS += $(patsubst %.rc,$(OBJ_DIR)/%.res,$(strip $(LIB_RCFILES)))
endif

TOCLEAN := $(libcurl_dll_OBJECTS)
TOVCLEAN := $(libcurl_dll_LIBRARY:.dll=.def) $(libcurl_dll_a_LIBRARY) $(libcurl_map_LIBRARY)

### Rules

$(libcurl_a_LIBRARY): $(libcurl_a_OBJECTS) $(libcurl_a_DEPENDENCIES)
	@$(call DEL, $@)
	$(AR) rcs $@ $(libcurl_a_OBJECTS)

$(libcurl_dll_LIBRARY): $(libcurl_dll_OBJECTS)
	$(CC) $(LDFLAGS) -shared $(CURL_LDFLAGS_LIB) -o $@ $(libcurl_dll_OBJECTS) $(LIBS) \
	  -Wl,--output-def,$(@:.dll=.def),--out-implib,$(libcurl_dll_a_LIBRARY)

all: $(OBJ_DIR) $(TARGETS)
endif
