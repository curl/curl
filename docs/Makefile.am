#
# $Id$
#

AUTOMAKE_OPTIONS = foreign no-dependencies

man_MANS = \
	curl.1 \
	curl-config.1

HTMLPAGES = \
	curl.html \
	curl-config.html

SUBDIRS = examples libcurl

EXTRA_DIST = MANUAL BUGS CONTRIBUTE FAQ FEATURES INTERNALS		\
	     README.win32 RESOURCES TODO TheArtOfHttpScripting THANKS	\
	     VERSIONS KNOWN_BUGS BINDINGS $(man_MANS) $(HTMLPAGES) \
	     HISTORY INSTALL

MAN2HTML= gnroff -man $< | man2html >$@

SUFFIXES = .1 .3 .html

html: $(HTMLPAGES)
	cd libcurl; make html

.3.html:
	$(MAN2HTML)

.1.html:
	$(MAN2HTML)
