#!/bin/sh
#
# Main curl test script
#
#######################################################################
# These should be the only variables that might be needed to get edited:

HOSTIP=127.0.0.1
HOSTPORT=8999
CURL=../src/curl
LOGDIR=log
SERVERIN=$LOGDIR/server.input
CURLOUT=$LOGDIR/curl.out
NC=nc

# Normally, all test cases should be run, but at times it is handy to
# simply run a particular one:
TESTCASES=" 1 2 3 4"


compare () {
  # filter off the $4 pattern before compare!

  first="$1"
  sec="$2"
  text="$3"
  strip="$4"

  if test -n "$strip"; then
    egrep -v "$strip" < $first > $LOGDIR/generated.tmp
    egrep -v "$strip" < $sec > $LOGDIR/stored.tmp

    first="$LOGDIR/generated.tmp"
    sec="$LOGDIR/stored.tmp"
  fi

  cmp $first $sec
  if [ $? != "0" ]; then
    echo " $text FAILED"
    return 1
  else
    echo " $text OK"
    return 0
  fi
}

singletest ()
{
  NUMBER="$1"

  REPLY=data/reply$NUMBER.txt
  CURLCMD=data/command$NUMBER.txt
  HTTP=data/http$NUMBER.txt
  DESC=`cat data/name$NUMBER.txt | tr -d '\012'`

  echo "test $NUMBER... [$DESC]"

  ./runserv.pl $HOSTIP $HOSTPORT &

  sleep 1

  # get the command line options to use
  cmd=`sed -e "s/%HOSTIP/$HOSTIP/g" -e "s/%HOSTPORT/$HOSTPORT/g" <$CURLCMD `

  # run curl
  CMDLINE="$CURL -o $CURLOUT -i --silent $cmd"

  # we do it the eval way to deal with quotes and similar stuff
  eval $CMDLINE

  if test -n "$verbose"; then
    echo "$CMDLINE"
  fi

  if [ $? != "0" ]; then
    echo "Failed to invoke curl for test $NUMBER"
  else
    # when curl is done, the server has closed down as well

    # verify the received data
    compare $CURLOUT $REPLY " fetch"

    if [ $? != "0" ]; then
      exit;
    fi

    # verify the sent request
    compare $SERVERIN $HTTP " command" "User-Agent:"

    if [ $? != "0" ]; then
      exit;
    fi
  fi

  return 0
}


#######################################################################
# Check options to this test program
#

if test "$1" = "-v"; then
  verbose="1"
fi

if test -n "$NEWSETUP"; then

  #######################################################################
  # Make sure the Host: lines are correct for this setup
  #

  HOST="$HOSTIP:$HOSTPORT"
  for test in data/http*.txt; do
   sed -e "s/Host: \([0-9.:]*\)/Host: $HOST/g" < $test > $test.tmp
   mv $test.tmp $test
  done
fi

#######################################################################
# Output curl version being tested
#
VERSION=`$CURL -V`

echo "Running tests on:"
echo $VERSION
echo ""

#######################################################################
# remove and recreate logging directory:
#
rm -rf $LOGDIR
mkdir $LOGDIR

#######################################################################
# First, start the TCP server
#
#./runserv.pl $HOSTIP $HOSTPORT &

#if [ $? != "0" ]; then
#  echo "failed starting the TCP server"
#  exit
#fi

#sleep 1 # give it a second to start

#######################################################################
# The main test-loop
#

for NUMBER in $TESTCASES; do

  singletest $NUMBER

  # loop for next test
done
