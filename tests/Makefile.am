EXTRA_DIST = ftpserver.pl httpserver.pl httpsserver.pl runtests.pl \
	     ftpsserver.pl stunnel.pm getpart.pm FILEFORMAT README \
	     stunnel.pem memanalyze.pl

SUBDIRS = data server libtest

PERLFLAGS = -I$(srcdir)

curl:
	@(cd ..; make)

test: server/sws
	@cd data && exec $(MAKE) test
	srcdir=$(srcdir) $(PERL) $(PERLFLAGS) $(srcdir)/runtests.pl

quiet-test: server/sws
	@cd data && exec $(MAKE) test
	srcdir=$(srcdir) $(PERL) $(PERLFLAGS) $(srcdir)/runtests.pl -s -a

full-test: server/sws
	@cd data && exec $(MAKE) test
	srcdir=$(srcdir) $(PERL) $(PERLFLAGS) $(srcdir)/runtests.pl -a

server/sws:
	cd server; make sws
