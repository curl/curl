#!/bin/sh

###########################
#  What is This Script?
###########################

# testcurl.sh is the master script to use for automatic testing of CVS-curl.
# This is written for the purpose of being run from a crontab job or similar
# at a regular interval. The output will be suitable to be mailed automaticly
# to "curl-autocompile@haxx.se" to be dealt with automatically.  The most
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

log() {
    text=$1
    if test -n "$text"; then
      echo "testcurl: $text"
    fi
}

die(){
    text=$1
    log "$text"

    if test -n "$pwd/$build"; then
      # we have a build directory name, remove the dir
      log "removing the $build dir"
      rm -rf "$pwd/$build"
    fi
    if test -r "$pwd/$buildlog"; then
      # we have a build log output file left, remove it
      log "removing the $buildlog file"
      rm -rf "$buildlog"
    fi
    log "ENDING HERE" # last line logged!
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

log "STARTING HERE" # first line logged
log "NAME = $name"
log "EMAIL = $email"
log "DESC = $desc"
log "CONFOPTS = $confopts"
log "version = $version"
log "date = `date -u`"

# Make $pwd to become the path without newline. We'll use that in order to cut
# off that path from all possible logs and error messages etc.
ipwd=`pwd` 
pwd=`echo $ipwd | sed -e 's/$//g'`

if [ -d "$CURLDIR" ]; then
  if [ $CVS -eq 1 -a -d $CURLDIR/CVS ]; then
    log "curl is verified to be a fine source dir"
  elif [ $CVS -eq 0 -a -f $CURLDIR/testcurl.sh ]; then
    log "curl is verified to be a fine daily source dir"
  else
    die "curl is not a daily source dir or checked out from CVS!"
  fi
fi
build="build-$$"
buildlog="buildlog-$$"

# remove any previous left-overs
rm -rf build-*

# create a dir to build in
mkdir $build

if [ -d $build ]; then
  log "build dir $build was created fine"
else
  die "failed to create dir $build"
fi

# get in the curl source tree root
cd $CURLDIR

# Do the CVS thing, or not...
if [ $CVS -eq 1 ]; then
  log "update from CVS"

  cvsup() {
    # update quietly to the latest CVS
    log "run cvs up"
    cvs -Q up -dP 2>&1

    cvsstat=$?

    # return (1 - RETURNVALUE) so that errors return 0 while goodness
    # returns 1
    return `expr 1 - $cvsstat`
  }

  att="0"
  while cvsup; do
    att=`expr $att + 1`
    log "failed CVS update attempt number $att."
    if [ $att -gt 10 ]; then
      cvsstat="111"
      break # get out of the loop
    fi
    sleep 5
  done
  
  if [ "$cvsstat" -ne "0" ]; then
    die "failed to update from CVS ($cvsstat), exiting"
  fi
  
  # remove possible left-overs from the past
  rm -f configure
  rm -rf autom4te.cache

  # generate the build files
  ./buildconf 2>&1 | tee $buildlog

  if { grep "^buildconf: OK" $buildlog >/dev/null 2>&1; } then
     log "buildconf was successful"
  else
     die "buildconf was NOT successful"
  fi

fi

if [ -f configure ]; then
  log "configure created"
else
  die "no configure created"
fi

# change to build dir
cd "../$build"

# run configure script
../$CURLDIR/configure $confopts 2>&1

if [ -f lib/Makefile ]; then
  log "configure seems to have finished fine"
else
  die "configure didn't work"
fi

log "display lib/config.h"
grep "^ *#" lib/config.h

if { grep "define USE_ARES" lib/config.h; } then
  log "setup to build ares"

  log "build ares"
  cd ares
  make 2>&1 | sed -e "s:$pwd::g"

  if [ -f libcares.a]; then
    log "ares is now built successfully"
  else
    log "ares build failed"
  fi

  # cd back to the curl build dir
  cd ..
fi

log "run make"
make -i 2>&1 | sed -e "s:$pwd::g"

if [ -f src/curl ]; then
  log "src/curl was created fine"
else
  die "src/curl was not created"
fi

log "run make test-full"
make test-full 2>&1 | sed -e "s:$pwd::g" | tee $buildlog

if { grep "^TEST" $buildlog >/dev/null 2>&1; } then
  log "tests were run"
else
  die "test suite failure"
fi

if { grep "^TESTFAIL:" $buildlog >/dev/null 2>&1; } then
  log "the tests were not successful"
else
  log "the tests were successful!"  
fi

# die to cleanup
die "ending nicely"
