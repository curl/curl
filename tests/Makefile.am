EXTRA_DIST = ftpserver.pl httpserver.pl runtests.pl

SUBDIRS = data

all:
install:

curl:
	@(cd ..; make)

test:
	$(PERL) runtests.pl

quiet-test:
	$(PERL) runtests.pl -s -a

clean:
	rm -rf log
	find . -name "*~" | xargs rm -f

