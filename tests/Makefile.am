EXTRA_DIST = ftpserver.pl httpserver.pl httpsserver.pl runtests.pl \
	     ftpsserver.pl stunnel.pm getpart.pm FILEFORMAT README \
	     stunnel.pem memanalyze.pl

SUBDIRS = data server

PERLFLAGS = -I$(srcdir)

all:
install:

curl:
	@(cd ..; make)

test: server/sws
	@cd data && exec $(MAKE) test
	srcdir=$(srcdir) $(PERL) $(PERLFLAGS) $(srcdir)/runtests.pl

quiet-test: server/sws
	@cd data && exec $(MAKE) test
	srcdir=$(srcdir) $(PERL) $(PERLFLAGS) $(srcdir)/runtests.pl -s -a

clean:
	rm -rf log
	find . -name "*~" | xargs rm -f

server/sws:
	cd server; make sws
