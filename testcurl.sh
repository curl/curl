#!/bin/sh
###########################
#  What is This Script?
###########################

# testcurl.sh is the master script to use for automatic testing of CVS-curl.
# This is written for the purpose of being run from a crontab job or similar
# at a regular interval. The output will be suitable to be mailed automaticly
# to "curl-autocompile@haxx.se" to be dealt with automaticly.  The most
# current build status (with a resonable backlog) will be published on the
# curl site, at http://curl.haxx.se/

# USAGE:
# testcurl.sh [configure options] > output

# version of this script
version=1
fixed=0

die(){
	echo "testcurl: ENDING HERE"
	exit 1
}

if [ -f setup ]; then
  . "./setup"
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


if [ "$fixed" -gt "0" ]; then
  echo "name='$name'" > setup
  echo "email='$email'" >> setup
  echo "desc='$desc'" >> setup
fi

echo "testcurl: STARTING HERE"
echo "testcurl: NAME = $name"
echo "testcurl: EMAIL = $email"
echo "testcurl: DESC = $desc"
echo "testcurl: version = $version"
echo "testcurl: confopts = $1"
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
rm -rf $build

# create a dir to build in
mkdir $build

# get in the curl source tree root
cd curl

echo "testcurl: update from CVS"
# update quietly to the latest CVS
cvs -Q up -dP 2>&1

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
../curl/configure $1 2>&1

if [ -f lib/Makefile ]; then
  echo "testcurl: configure seems to have finished fine"
else
  echo "testcurl: configure didn't work"
  die
fi

echo "testcurl: now run make"
make 2>&1 | sed -e "s:$pwd::g"

if [ -f src/curl ]; then
  echo "testcurl: src/curl was created fine"
else
  echo "testcurl: src/curl was not created"
  die
fi

echo "testcurl: now run make test"
make test 2>&1 | sed -e "s:$pwd::g" | tee build.log

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
