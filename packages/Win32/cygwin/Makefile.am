EXTRA_DIST = README

#
# Build a Cygwin binary tar ball
#
# Read the README file for details on using this Makefile
#
# NOTE: As I'm not particularly familiar with Makefiles, this was the
#  best I could come up with. It should probably be enhanced someday 
#  to actually use the correct target and pre-requisite names, etc...
#  If anyone else wants to volunteer, feel free ;-)
#

# Cygwin build number (default to "1")
CYGBUILD = 1

# Cygwin tarball build dir (fully-qualified name, gets deleted when done)
cygwintmp = $(CURDIR)/cygwinbin-builddir

cygwinbin:
	rm -rf $(cygwintmp)
	$(MAKE) -C $(top_builddir) install-strip prefix=$(cygwintmp)/usr
	$(mkinstalldirs) $(cygwintmp)/usr/doc/Cygwin \
	                 $(cygwintmp)/usr/doc/$(PACKAGE)-$(VERSION)
	cd $(top_srcdir); \
	  cp packages/Win32/cygwin/README \
	  $(cygwintmp)/usr/doc/Cygwin/$(PACKAGE)-$(VERSION)-$(CYGBUILD).README
	cd $(top_srcdir) ; \
	  cp CHANGES LEGAL MPL-1.1.txt README docs/FAQ docs/FEATURES docs/TODO \
	  $(cygwintmp)/usr/doc/$(PACKAGE)-$(VERSION)
	cd $(cygwintmp) ; \
	  tar cjf $(PACKAGE)-$(VERSION)-$(CYGBUILD).tar.bz2 usr
	mv $(cygwintmp)/$(PACKAGE)-$(VERSION)-$(CYGBUILD).tar.bz2 . \
	  && rm -rf $(cygwintmp)
