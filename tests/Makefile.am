
all:
install:

curl:
	@(cd ..; make)

test:
	perl runtests.pl

quiet-test:
	perl runtests.pl -s -a

clean:
	rm -rf log
	find . -name "*~" | xargs rm -f

