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
###########################################################################

AUTOMAKE_OPTIONS = foreign no-dependencies

if BUILD_DOCS
# if we disable man page building, ignore these
MK_CA_DOCS = mk-ca-bundle.1
CURLCONF_DOCS = curl-config.1
endif

CURLPAGES = curl-config.md mk-ca-bundle.md

SUBDIRS = . cmdline-opts libcurl
DIST_SUBDIRS = $(SUBDIRS) examples

if BUILD_DOCS
CLEANFILES = mk-ca-bundle.1 curl-config.1
endif

EXTRA_DIST =                                    \
 $(CURLPAGES)                                   \
 ALTSVC.md                                      \
 BINDINGS.md                                    \
 BUFQ.md                                        \
 BUFREF.md                                      \
 BUG-BOUNTY.md                                  \
 BUGS.md                                        \
 CHECKSRC.md                                    \
 CIPHERS.md                                     \
 CMakeLists.txt                                 \
 CODE_OF_CONDUCT.md                             \
 CODE_REVIEW.md                                 \
 CODE_STYLE.md                                  \
 CLIENT-READERS.md                              \
 CLIENT-WRITERS.md                              \
 CONNECTION-FILTERS.md                          \
 CONTRIBUTE.md                                  \
 CURL-DISABLE.md                                \
 CURLDOWN.md                                    \
 DEPRECATE.md                                   \
 DISTROS.md                                     \
 DYNBUF.md                                      \
 EARLY-RELEASE.md                               \
 ECH.md                                         \
 EXPERIMENTAL.md                                \
 FAQ                                            \
 FEATURES.md                                    \
 GOVERNANCE.md                                  \
 HELP-US.md                                     \
 HISTORY.md                                     \
 HSTS.md                                        \
 HTTP-COOKIES.md                                \
 HTTP2.md                                       \
 HTTP3.md                                       \
 HYPER.md                                       \
 INSTALL                                        \
 INSTALL-CMAKE.md                               \
 INSTALL.md                                     \
 INTERNALS.md                                   \
 IPFS.md                                        \
 KNOWN_BUGS                                     \
 MAIL-ETIQUETTE.md                              \
 MANUAL.md                                      \
 MQTT.md                                        \
 NEW-PROTOCOL.md                                \
 options-in-versions                            \
 PARALLEL-TRANSFERS.md                          \
 README.md                                      \
 RELEASE-PROCEDURE.md                           \
 RUSTLS.md                                      \
 ROADMAP.md                                     \
 SECURITY-ADVISORY.md                           \
 SPONSORS.md                                    \
 SSL-PROBLEMS.md                                \
 SSLCERTS.md                                    \
 THANKS                                         \
 TODO                                           \
 TheArtOfHttpScripting.md                       \
 URL-SYNTAX.md                                  \
 VERSIONS.md                                    \
 VULN-DISCLOSURE-POLICY.md                      \
 WEBSOCKET.md

CD2NROFF = $(top_srcdir)/scripts/cd2nroff $< >$@

CD2 = $(CD2_$(V))
CD2_0 = @echo "  RENDER " $@;
CD2_1 =
CD2_ = $(CD2_0)

SUFFIXES = .1 .md

all: $(MK_CA_DOCS) $(CURLCONF_DOCS)

.md.1:
	$(CD2)$(CD2NROFF)

curl-config.1: curl-config.md

mk-ca-bundle.1: mk-ca-bundle.md

distclean:
	rm -f $(CLEANFILES)
