EXTRA_DIST = ftpserver.pl httpserver.pl httpsserver.pl runtests.pl \
	     ftpsserver.pl stunnel.pm getpart.pm FILEFORMAT README \
	     stunnel.pem memanalyze.pl

SUBDIRS = data server libtest

PERLFLAGS = -I$(srcdir)

curl:
	@cd $(top_builddir) && $(MAKE)

test: sws
	@cd data && exec $(MAKE) test
	srcdir=$(srcdir) $(PERL) $(PERLFLAGS) $(srcdir)/runtests.pl

quiet-test: sws
	@cd data && exec $(MAKE) test
	srcdir=$(srcdir) $(PERL) $(PERLFLAGS) $(srcdir)/runtests.pl -s -a

full-test: sws
	@cd data && exec $(MAKE) test
	srcdir=$(srcdir) $(PERL) $(PERLFLAGS) $(srcdir)/runtests.pl -a

sws:
	@cd server && $(MAKE)
