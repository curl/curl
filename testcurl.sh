#!/bin/sh
###########################
#  What is This Script?
###########################

# testcurl.sh is the master script to use for automatic testing of CVS-curl.
# This is written for the purpose of being run from a crontab job or similar
# at a regular interval. The output will be suitable to be mailed automaticly
# to "curl-autocompile@haxx.se" to be dealt with automaticly.  The most
# current build status (with a resonable backlog) will be published on the
# curl site, at http://curl.haxx.se/auto/

# USAGE:
# testcurl.sh > output

# version of this script
version=1
fixed=0

LANG="C"

export LANG

die(){
    echo "testcurl: ENDING HERE"
    exit 1
}

if [ -f setup ]; then
  . "./setup"
  infixed="$fixed"
fi

if [ -z "$name" ]; then
  echo "please enter your name"
  read name
  fixed="1"
fi

if [ -z "$email" ]; then
  echo "please enter your contact email address"
  read email
  fixed="2"
fi

if [ -z "$desc" ]; then
  echo "please enter a one line system desrciption"
  read desc
  fixed="3"
fi

if [ -z "$confopts" ]; then
  if [ $infixed -lt 4 ]; then
    echo "please enter your additional arguments to configure"
    echo "examples: --with-ssl --enable-debug --enable-ipv6 --with-krb4"
    read confopts
    fixed="4"
  fi
fi


if [ "$fixed" -gt "0" ]; then
  echo "name='$name'" > setup
  echo "email='$email'" >> setup
  echo "desc='$desc'" >> setup
  echo "confopts='$confopts'" >> setup
  echo "fixed='$fixed'" >> setup
fi

echo "testcurl: STARTING HERE"
echo "testcurl: NAME = $name"
echo "testcurl: EMAIL = $email"
echo "testcurl: DESC = $desc"
echo "testcurl: CONFOPTS = $confopts"
echo "testcurl: version = $version"
echo "testcurl: date = `date -u`"

# Make $pwd to become the path without newline. We'll use that in order to cut
# off that path from all possible logs and error messages etc.
ipwd=`pwd` 
pwd=`echo $ipwd | sed -e 's/$//g'`

if [ -d curl -a -d curl/CVS ]; then
  echo "testcurl: curl is verified to be a fine source dir"
else
  echo "testcurl: curl is not a source dir checked out from CVS!"
  die
fi

build="build-$$"

# remove any previous left-overs
rm -rf build-*

# create a dir to build in
mkdir $build

if [ -d $build ]; then
  echo "testcurl: build dir $build was created fine"
else
  echo "testcurl: failed to create dir $build"
  die
fi

# get in the curl source tree root
cd curl

echo "testcurl: update from CVS"
# update quietly to the latest CVS
cvs -Q up -dP 2>&1

cvsstat=$?
echo "testcurl: cvs returned: $cvsstat"

# figure out the current collected CVS status
newstat="../allcvs.log"
oldstat="../oldcvs.log"
find . -name Entries -exec cat {} \; > "$newstat"

if [ -r "$oldstat" ]; then
  # there is a previous cvs stat file to compare with
  if { cmp "$oldstat" "$newstat"; } then
    echo "testcurl: this is the same CVS status as before"
    echo "testcurl: ALREADY TESTED THIS SETUP BEFORE"
    #die
  else
    echo "testcurl: there has been a change in the CVS"
  fi
fi

# remove possible left-overs from the past
rm -f configure
rm -rf autom4te.cache

# generate the build files
./buildconf 2>&1

if [ -f configure ]; then
  echo "testcurl: configure created"
else
  echo "testcurl: no configure created"
  die
fi

# change to build dir
cd "../$build"

# run configure script
../curl/configure $confopts 2>&1

if [ -f lib/Makefile ]; then
  echo "testcurl: configure seems to have finished fine"
else
  echo "testcurl: configure didn't work"
  die
fi

echo "testcurl: display lib/config.h"
grep "^ *#" lib/config.h

echo "testcurl: now run make"
make -i 2>&1 | sed -e "s:$pwd::g"

if [ -f src/curl ]; then
  echo "testcurl: src/curl was created fine"
else
  echo "testcurl: src/curl was not created"
  die
fi

echo "testcurl: now run make test-full"
make test-full 2>&1 | sed -e "s:$pwd::g" | tee build.log

if { grep "^TESTFAIL:" build.log; } then
  echo "testcurl: the tests were not successful"
else
  echo "testcurl: the tests were successful!"  
fi

# store the cvs status for the next time
mv $newstat $oldstat

# get out of dir
cd ..

# delete build dir
rm -rf "$build"

die
