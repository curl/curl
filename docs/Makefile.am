#***************************************************************************
#                                  _   _ ____  _
#  Project                     ___| | | |  _ \| |
#                             / __| | | | |_) | |
#                            | (__| |_| |  _ <| |___
#                             \___|\___/|_| \_\_____|
#
# Copyright (C) 1998 - 2019, Daniel Stenberg, <daniel@haxx.se>, et al.
#
# This software is licensed as described in the file COPYING, which
# you should have received as part of this distribution. The terms
# are also available at https://curl.haxx.se/docs/copyright.html.
#
# You may opt to use, copy, modify, merge, publish, distribute and/or sell
# copies of the Software, and permit persons to whom the Software is
# furnished to do so, under the terms of the COPYING file.
#
# This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
# KIND, either express or implied.
#
###########################################################################

AUTOMAKE_OPTIONS = foreign no-dependencies

# EXTRA_DIST breaks with $(abs_builddir) so build it using this variable
# but distribute it (using the relative file name) in the next variable
man_MANS = $(abs_builddir)/curl.1
noinst_man_MANS = curl.1 mk-ca-bundle.1
dist_man_MANS = curl-config.1
GENHTMLPAGES = curl.html curl-config.html mk-ca-bundle.html
PDFPAGES = curl.pdf curl-config.pdf mk-ca-bundle.pdf
MANDISTPAGES = curl.1.dist curl-config.1.dist

HTMLPAGES = $(GENHTMLPAGES) index.html

# Build targets in this file (.) before cmdline-opts to ensure that
# the curl.1 rule below runs first
SUBDIRS = . cmdline-opts
DIST_SUBDIRS = $(SUBDIRS) examples libcurl

CLEANFILES = $(GENHTMLPAGES) $(PDFPAGES) $(MANDISTPAGES) curl.1

EXTRA_DIST =                                    \
 $(noinst_man_MANS)                             \
 ALTSVC.md                                      \
 BINDINGS.md                                    \
 BUG-BOUNTY.md                                  \
 BUGS                                           \
 CHECKSRC.md                                    \
 CIPHERS.md                                     \
 CMakeLists.txt                                 \
 CODE_OF_CONDUCT.md                             \
 CODE_STYLE.md                                  \
 CONTRIBUTE.md                                  \
 CURL-DISABLE.md                                \
 DEPRECATE.md                                   \
 ESNI.md                                        \
 EXPERIMENTAL.md                                \
 FAQ                                            \
 FEATURES                                       \
 GOVERNANCE.md                                  \
 HELP-US.md                                     \
 HISTORY.md                                     \
 HTTP-COOKIES.md                                \
 HTTP2.md                                       \
 HTTP3.md                                       \
 INSTALL                                        \
 INSTALL.cmake                                  \
 INSTALL.md                                     \
 INTERNALS.md                                   \
 KNOWN_BUGS                                     \
 LICENSE-MIXING.md                              \
 MAIL-ETIQUETTE                                 \
 PARALLEL-TRANSFERS.md                          \
 README.cmake                                   \
 README.md                                      \
 README.netware                                 \
 README.win32                                   \
 RELEASE-PROCEDURE.md                           \
 RESOURCES                                      \
 ROADMAP.md                                     \
 SECURITY-PROCESS.md                            \
 SSL-PROBLEMS.md                                \
 SSLCERTS.md                                    \
 THANKS                                         \
 TODO                                           \
 TheArtOfHttpScripting                          \
 VERSIONS

MAN2HTML= roffit $< >$@

SUFFIXES = .1 .html .pdf

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
		$(INSTALL_DATA) "$(srcdir)/curl.1" $@; fi
	cd cmdline-opts && $(MAKE)

html: $(HTMLPAGES)
	cd libcurl && $(MAKE) html

pdf: $(PDFPAGES)
	cd libcurl && $(MAKE) pdf

.1.html:
	$(MAN2HTML)

.1.pdf:
	@(foo=`echo $@ | sed -e 's/\.[0-9]$$//g'`; \
	groff -Tps -man $< >$$foo.ps; \
	ps2pdf $$foo.ps $@; \
	rm $$foo.ps; \
	echo "converted $< to $@")

distclean:
	rm -f $(CLEANFILES)
