#
# $Id$
#

AUTOMAKE_OPTIONS = foreign no-dependencies

man_MANS = \
	curl.1 \
	curl-config.1

HTMLPAGES = \
	curl.html \
	curl-config.html \
	index.html

PDFPAGES = \
	curl.pdf \
	curl-config.pdf

SUBDIRS = examples libcurl

EXTRA_DIST = MANUAL BUGS CONTRIBUTE FAQ FEATURES INTERNALS		\
	     README.win32 RESOURCES TODO TheArtOfHttpScripting THANKS	\
	     VERSIONS KNOWN_BUGS BINDINGS $(man_MANS) $(HTMLPAGES) \
	     HISTORY INSTALL libcurl-the-guide $(PDFPAGES)

MAN2HTML= gnroff -man $< | man2html >$@

SUFFIXES = .1 .3 .html .pdf

html: $(HTMLPAGES)
	cd libcurl; make html

.3.html:
	$(MAN2HTML)

.1.html:
	$(MAN2HTML)

MAN2PDF = groff -Tps -man curl.1 $< >$@

pdf:
	for file in $(man_MANS); do \
	  foo=`echo $$file | sed -e 's/\.[0-9]$$//g'`; \
	  groff -Tps -man $$file >$$foo.ps; \
	  ps2pdf $$foo.ps $$foo.pdf; \
	done
	cd libcurl; make pdf
