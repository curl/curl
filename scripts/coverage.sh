#!/bin/sh

./buildconf
mkdir -p cvr
cd cvr
../configure --disable-shared --enable-debug --enable-maintainer-mode --enable-code-coverage
make -sj
# the regular test run
make TFLAGS=-n test-nonflaky
# make all allocs/file operations fail
#make TFLAGS=-n test-torture
# do everything event-based
make TFLAGS=-n test-event
lcov -d . -c -o cov.lcov
genhtml cov.lcov --output-directory coverage --title "curl code coverage"
tar -cjf curl-coverage.tar.bz2 coverage
