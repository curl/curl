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

# See usage in lib/Makefile.mk

PROOT := ..

### Common

include $(PROOT)/lib/Makefile.mk

### Local

CPPFLAGS += -I$(PROOT)/lib
LDFLAGS  += -L$(PROOT)/lib
LIBS     := -lcurl $(LIBS)

### Sources and targets

# Provides CURL_CFILES, CURLX_CFILES
include Makefile.inc

TARGETS := curl$(BIN_EXT)

CURL_CFILES += $(notdir $(CURLX_CFILES))

ifneq ($(CURL_CA_EMBED),)
CPPFLAGS += -DCURL_CA_EMBED
CURL_CFILES += tool_ca_embed.c
endif

curl_OBJECTS := $(patsubst %.c,$(OBJ_DIR)/%.o,$(strip $(CURL_CFILES)))
ifdef MAP
CURL_MAP := curl.map
LDFLAGS += -Wl,-Map,$(CURL_MAP)
TOVCLEAN := $(CURL_MAP)
endif
vpath %.c $(PROOT)/lib

TOCLEAN := $(curl_OBJECTS)

### Rules

PERL ?= perl

ifneq ($(wildcard tool_hugehelp.c.cvs),)
TOCLEAN += tool_hugehelp.c
# Load DPAGES
include $(PROOT)/docs/cmdline-opts/Makefile.inc
$(PROOT)/docs/cmdline-opts/curl.txt: $(addprefix $(PROOT)/docs/cmdline-opts/,$(DPAGES)) $(PROOT)/scripts/managen
	cd $(PROOT)/docs/cmdline-opts && $(PERL) ../../scripts/managen ascii $(DPAGES) > curl.txt
# Necessary for the generated tools_hugehelp.c
CPPFLAGS += -DUSE_MANUAL
ifdef ZLIB
_MKHELPOPT += -c
endif
tool_hugehelp.c: $(PROOT)/docs/cmdline-opts/curl.txt mkhelp.pl
	$(PERL) mkhelp.pl $(_MKHELPOPT) < $< > $@
else
tool_hugehelp.c:
	@echo Creating $@
	@$(call COPY, $@.cvs, $@)
endif

ifneq ($(CURL_CA_EMBED),)
TOCLEAN += tool_ca_embed.c
tool_ca_embed.c: mk-file-embed.pl
	$(PERL) mk-file-embed.pl --var curl_ca_embed < $(CURL_CA_EMBED) > $@
endif

$(TARGETS): $(curl_OBJECTS) $(PROOT)/lib/libcurl.a
	$(CC) $(LDFLAGS) -o $@ $(curl_OBJECTS) $(LIBS)

all: $(OBJ_DIR) $(TARGETS)
