EXTRA_DIST = data ftpserver.pl httpserver.pl runtests.pl

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

