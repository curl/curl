#
# $Id$
#

AUTOMAKE_OPTIONS = foreign no-dependencies

man_MANS = \
	curl.1 \
	curl-config.1 \
	curl_easy_cleanup.3 \
	curl_easy_getinfo.3 \
	curl_easy_init.3 \
	curl_easy_perform.3 \
	curl_easy_setopt.3 \
	curl_formparse.3 \
	curl_formadd.3 \
	curl_formfree.3 \
	curl_getdate.3 \
	curl_getenv.3 \
	curl_slist_append.3 \
	curl_slist_free_all.3 \
	curl_version.3 \
	curl_escape.3 \
	curl_unescape.3 \
	curl_strequal.3 \
	curl_strnequal.3 \
	curl_mprintf.3 \
	curl_global_init.3 \
	curl_global_cleanup.3 \
	libcurl.3

SUBDIRS = examples

HTMLPAGES = \
	curl.html \
	curl-config.html \
	curl_easy_cleanup.html \
	curl_easy_getinfo.html \
	curl_easy_init.html \
	curl_easy_perform.html \
	curl_easy_setopt.html \
	curl_formadd.html \
	curl_formparse.html \
	curl_formfree.html \
	curl_getdate.html \
	curl_getenv.html \
	curl_slist_append.html \
	curl_slist_free_all.html \
	curl_version.html \
	curl_escape.html \
	curl_unescape.html \
	curl_strequal.html \
	curl_strnequal.html \
	curl_mprintf.html \
	curl_global_init.html \
	curl_global_cleanup.html \
	libcurl.html

EXTRA_DIST = $(man_MANS) \
	MANUAL BUGS CONTRIBUTE FAQ FEATURES INTERNALS \
	README.win32 RESOURCES TODO TheArtOfHttpScripting THANKS \
	$(HTMLPAGES)

MAN2HTML= gnroff -man $< | man2html >$@

SUFFIXES = .1 .3 .html

html: $(HTMLPAGES)

.3.html:
	$(MAN2HTML)

.1.html:
	$(MAN2HTML)
