EXTRA_DIST = ftpserver.pl httpserver.pl httpsserver.pl runtests.pl \
	     ftpsserver.pl stunnel.pm getpart.pm FILEFORMAT README

SUBDIRS = data

PERLFLAGS = -I$(srcdir)

all:
install:

curl:
	@(cd ..; make)

test:
	@cd data && exec $(MAKE) test
	srcdir=$(srcdir) $(PERL) $(PERLFLAGS) $(srcdir)/runtests.pl

quiet-test:
	@cd data && exec $(MAKE) test
	srcdir=$(srcdir) $(PERL) $(PERLFLAGS) $(srcdir)/runtests.pl -s -a

clean:
	rm -rf log
	find . -name "*~" | xargs rm -f

