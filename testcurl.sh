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
# testcurl.sh [curl-daily-name] > output

# Updated: 
# v1.1 6-Nov-03 - to take an optional parameter, the name of a daily-build
#                 directory.  If present, build from that directory, otherwise
#                 perform a normal CVS build.

# version of this script
version=1.1
fixed=0

# Determine if we're running from CVS or a canned copy of curl
if [ "$#" -ge "1" -a "$1" ]; then
  CURLDIR=$1
  CVS=0
else
  CURLDIR="curl"
  CVS=1
fi

LANG="C"

export LANG

die(){
    echo "testcurl: ENDING HERE"
    if test -n "$build"; then
      # we have a build directory name, remove the dir
      rm -rf $build
    fi
    exit 1
}

if [ -f setup ]; then
  . "./setup"
  infixed="$fixed"
else
  infixed=0		# so that "additional args to configure" works properly first time...
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
  echo "please enter a one line system description"
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

if [ -d "$CURLDIR" ]; then
  if [ $CVS -eq 1 -a -d $CURLDIR/CVS ]; then
    echo "testcurl: curl is verified to be a fine source dir"
  elif [ $CVS -eq 0 -a -f $CURLDIR/testcurl.sh ]; then
    echo "testcurl: curl is verified to be a fine daily source dir"
  else
    echo "testcurl: curl is not a daily source dir or checked out from CVS!"
    die
  fi
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
cd $CURLDIR

# Do the CVS thing, or not...
if [ $CVS -eq 1 ]; then
  echo "testcurl: update from CVS"

  cvsup() {
    # update quietly to the latest CVS
    echo "testcurl: run cvs up"
    cvs -Q up -dP 2>&1

    cvsstat=$?

    # return (1 - RETURNVALUE) so that errors return 0 while goodness
    # returns 1
    return `expr 1 - $cvsstat`
  }

  att="0"
  while cvsup; do
    att=`expr $att + 1`
    echo "testcurl: failed CVS update attempt number $att."
    if [ $att -gt 10 ]; then
      cvsstat="111"
      break # get out of the loop
    fi
    sleep 5
  done
  
  echo "testcurl: cvs returned: $cvsstat"
  
  if [ "$cvsstat" -ne "0" ]; then
    echo "testcurl: failed to update from CVS, exiting"
    die
  fi
  
  # remove possible left-overs from the past
  rm -f configure
  rm -rf autom4te.cache

  # generate the build files
  ./buildconf 2>&1 | tee build.log

  if { grep "^buildconf: OK" build.log >/dev/null 2>&1; } then
     echo "testcurl: buildconf was successful"
  else
     echo "testcurl: buildconf was NOT successful"
     die
  fi

fi

if [ -f configure ]; then
  echo "testcurl: configure created"
else
  echo "testcurl: no configure created"
  die
fi

# change to build dir
cd "../$build"

# run configure script
../$CURLDIR/configure $confopts 2>&1

if [ -f lib/Makefile ]; then
  echo "testcurl: configure seems to have finished fine"
else
  echo "testcurl: configure didn't work"
  die
fi

echo "testcurl: display lib/config.h"
grep "^ *#" lib/config.h

if { grep "define USE_ARES" lib/config.h; } then
  echo "testcurl: setup to build ares"

  echo "testcurl: build ares"
  cd ares
  make
  echo "testcurl: ares is now built"

  # cd back to the curl build dir
  cd ..
fi

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

# get out of dir
cd ..

# delete build dir
rm -rf "$build"

die
