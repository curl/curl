EXTRA_DIST = ftpserver.pl httpserver.pl runtests.pl

SUBDIRS = data

all:
install:

curl:
	@(cd ..; make)

test:
	$(MAKE) -C data test
	srcdir=$(srcdir) $(PERL) $(srcdir)/runtests.pl

quiet-test:
	$(MAKE) -C data test
	srcdir=$(srcdir) $(PERL) $(srcdir)/runtests.pl -s -a

clean:
	rm -rf log
	find . -name "*~" | xargs rm -f

