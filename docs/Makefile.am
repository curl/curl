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

# EXTRA_DIST breaks with $(abs_builddir) so build it using this variable
# but distribute it (using the relative file name) in the next variable
man_MANS = $(abs_builddir)/curl.1 mk-ca-bundle.1
noinst_man_MANS = curl.1 mk-ca-bundle.1
dist_man_MANS = curl-config.1
CURLPAGES = curl-config.md mk-ca-bundle.md

# Build targets in this file (.) before cmdline-opts to ensure that
# the curl.1 rule below runs first
SUBDIRS = . cmdline-opts libcurl
DIST_SUBDIRS = $(SUBDIRS) examples

CLEANFILES = $(man_MANS) curl.1 curl-config.1 mk-ca-bundle.1
nodist_MANS = $(CLEANFILES)

EXTRA_DIST =                                    \
 $(CURLPAGES)                                   \
 ALTSVC.md                                      \
 BINDINGS.md                                    \
 BUFREF.md                                      \
 BUG-BOUNTY.md                                  \
 BUGS.md                                        \
 CHECKSRC.md                                    \
 CIPHERS.md                                     \
 CMakeLists.txt                                 \
 CODE_OF_CONDUCT.md                             \
 CODE_REVIEW.md                                 \
 CODE_STYLE.md                                  \
 CLIENT-WRITERS.md                              \
 CONNECTION-FILTERS.md                          \
 CONTRIBUTE.md                                  \
 CURL-DISABLE.md                                \
 CURLDOWN.md                                    \
 DEPRECATE.md                                   \
 DYNBUF.md                                      \
 EARLY-RELEASE.md                               \
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
 KNOWN_BUGS                                     \
 MAIL-ETIQUETTE                                 \
 MQTT.md                                        \
 NEW-PROTOCOL.md                                \
 options-in-versions                            \
 PARALLEL-TRANSFERS.md                          \
 README.md                                      \
 RELEASE-PROCEDURE.md                           \
 RUSTLS.md                                      \
 ROADMAP.md                                     \
 SECURITY-ADVISORY.md                           \
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

# $(abs_builddir) is to disable VPATH when searching for this file, which
# would otherwise find the copy in $(srcdir) which breaks the $(HUGE)
# rule in src/Makefile.am in out-of-tree builds that references the file in the
# build directory.
#
# First, seed the used copy of curl.1 with the prebuilt copy (in an out-of-tree
# build), then run make recursively to rebuild it only if its dependencies
# have changed.
$(abs_builddir)/curl.1:
	if test "$(top_builddir)x" != "$(top_srcdir)x" -a -e "$(srcdir)/curl.1"; then \
		$(INSTALL_DATA) "$(srcdir)/curl.1" $@ \
		&& touch -r "$(srcdir)/curl.1" $@; fi
	cd cmdline-opts && $(MAKE)

.md.1:
	$(CD2)$(CD2NROFF)

curl-config.1: curl-config.md

distclean:
	rm -f $(CLEANFILES)
