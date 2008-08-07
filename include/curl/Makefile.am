pkginclude_HEADERS = \
	curl.h curlver.h easy.h mprintf.h stdcheaders.h types.h multi.h \
	typecheck-gcc.h curlbuild.h curlrules.h

pkgincludedir= $(includedir)/curl

# curlbuild.h does not exist in the CVS tree. When the original libcurl
# source code distribution archive file is created, curlbuild.h.dist is
# renamed to curlbuild.h and included in the tarball so that it can be
# used directly on non-configure systems.
#
# The distributed curlbuild.h will be overwritten on configure systems
# when the configure script runs, with one that is suitable and specific
# to the library being configured and built.
#
# curlbuild.h.in is the distributed template file from which the configure
# script creates curlbuild.h at library configuration time, overwiting the
# one included in the distribution archive.
#
# curlbuild.h.dist is not included in the source code distribution archive.

EXTRA_DIST = curlbuild.h.in

DISTCLEANFILES = curlbuild.h

