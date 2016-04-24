iall:
install:
test:

# TESTCASES are taken from Makefile.inc
include Makefile.inc

EXTRA_DIST = $(TESTCASES) DISABLED CMakeLists.txt

filecheck:
	@mkdir test-place; \
	cp "$(top_srcdir)"/tests/data/test[0-9]* test-place/; \
	rm test-place/*~; \
	for f in $(EXTRA_DIST); do \
	  if test -f "$(top_srcdir)/tests/data/$$f"; then \
	    rm -f "test-place/$$f"; \
	  else \
	    echo "$$f is listed but missing!"; \
	  fi \
	done; \
	echo "Local files not present in EXTRA_DIST:" ; \
	ls test-place; \
	! ls test-place | grep . >/dev/null ; \
	RC=$$? ; \
	rm -rf test-place ; \
	exit $$RC

show:
	@echo $(EXTRA_DIST)
