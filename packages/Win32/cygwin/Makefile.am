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
cygwintmp = $(CURDIR)/tmp_binbuild

cygwinbin:
	rm -rf $(cygwintmp)
	rm -rf $(cygwintmp)-dev
	$(MAKE) -C $(top_builddir) DESTDIR=$(cygwintmp) install-strip
# $(STRIP) $(cygwintmp)/usr/bin/cygcurl-?.dll
	$(mkinstalldirs) \
	  $(cygwintmp)/usr/doc/Cygwin \
	  $(cygwintmp)/usr/doc/$(PACKAGE)-$(VERSION) \
	  $(cygwintmp)-dev/usr/doc/$(PACKAGE)-$(VERSION)/libcurl \
	  $(cygwintmp)-dev/usr/doc/$(PACKAGE)-$(VERSION)/examples \
	  $(cygwintmp)-dev/usr/man
#
# copy some files into the binary install dir
	cp $(srcdir)/README \
	  $(cygwintmp)/usr/doc/Cygwin/$(PACKAGE)-$(VERSION)-$(CYGBUILD).README
	cd $(top_srcdir) ; cp CHANGES COPYING README RELEASE-NOTES docs/* \
	  $(cygwintmp)/usr/doc/$(PACKAGE)-$(VERSION) ; pwd
	cd $(cygwintmp)/usr/doc/$(PACKAGE)-$(VERSION) ; rm *.1 Makefile*
#
# copy some files into the -dev install dir, remove some from binary
	cp $(top_srcdir)/docs/libcurl/*.html \
	  $(cygwintmp)-dev/usr/doc/$(PACKAGE)-$(VERSION)/libcurl
	cp $(top_srcdir)/docs/examples/* \
	  $(cygwintmp)-dev/usr/doc/$(PACKAGE)-$(VERSION)/examples
	rm $(cygwintmp)-dev/usr/doc/$(PACKAGE)-$(VERSION)/examples/Makefile*
	cp $(top_srcdir)/docs/examples/Makefile.example \
	  $(cygwintmp)-dev/usr/doc/$(PACKAGE)-$(VERSION)/examples
	mv $(cygwintmp)/usr/doc/$(PACKAGE)-$(VERSION)/BINDINGS \
	   $(cygwintmp)-dev/usr/doc/$(PACKAGE)-$(VERSION)
	mv $(cygwintmp)/usr/doc/$(PACKAGE)-$(VERSION)/INTERNALS \
	   $(cygwintmp)-dev/usr/doc/$(PACKAGE)-$(VERSION)
	mv $(cygwintmp)/usr/include $(cygwintmp)-dev/usr
	mv $(cygwintmp)/usr/lib $(cygwintmp)-dev/usr
	mv $(cygwintmp)/usr/man/man3 $(cygwintmp)-dev/usr/man
#
# create both tar files, and delete tmp folders
	cd $(cygwintmp) ; tar cjf \
	  $(PACKAGE)-$(VERSION)-$(CYGBUILD).tar.bz2 usr
	mv $(cygwintmp)/*.tar.bz2 . && rm -rf $(cygwintmp)
#
	cd $(cygwintmp)-dev ; tar cjf \
	  $(PACKAGE)-devel-$(VERSION)-$(CYGBUILD).tar.bz2 usr
	mv $(cygwintmp)-dev/*.tar.bz2 . && rm -rf $(cygwintmp)-dev

