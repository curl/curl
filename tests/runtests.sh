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
TESTCASES="9"

#######################################################################
# No variables below this point should need to be modified
#

PIDFILE=".server.pid"

stopserver() {
  # check for pidfile
  if [ -f $PIDFILE ] ; then
      PID=`cat $PIDFILE`
      kill -9 $PID
  fi
}

runserver () {
  # check for pidfile
  if [ -f $PIDFILE ] ; then
      PID=`cat $PIDFILE`
      if [ "x$PID" != "x" ] && kill -0 $PID 2>/dev/null ; then
          STATUS="httpd (pid $PID) running"
          RUNNING=1
      else
          STATUS="httpd (pid $PID?) not running"
          RUNNING=0
      fi
  else
      STATUS="httpd (no pid file) not running"
      RUNNING=0
  fi

  if [ $RUNNING != "1" ]; then
    ./httpserver.pl $HOSTPORT &
    sleep 1 # give it a little time to start
  else
    echo $STATUS
  fi
}

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

  # get the command line options to use
  cmd=`sed -e "s/%HOSTIP/$HOSTIP/g" \
           -e "s/%HOSTPORT/$HOSTPORT/g" \
           -e "s/%HOSTNAME/$HOSTNAME/g" <$CURLCMD `

  # run curl
  CMDLINE="$CURL -o $CURLOUT -i --silent $cmd"

  if test -n "$verbose"; then
    echo "$CMDLINE"
  fi

  # we do it the eval way to deal with quotes and similar stuff
  eval $CMDLINE

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
    compare $SERVERIN $HTTP " command" \
     "(User-Agent:|^--curl|Content-Type: multipart/form-data; boundary=)"

    #
    # The strip pattern above is for stripping off User-Agent: since that'll
    # be different in all versions, and the lines in a RFC1876-post that are
    # randomly generated and therefore are doomed to always differ!
    #


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
HOSTNAME=`hostname`

echo "Running tests on:"
echo $VERSION
echo "host $HOSTNAME"

#######################################################################
# remove and recreate logging directory:
#
rm -rf $LOGDIR
mkdir $LOGDIR

#######################################################################
# First, start the TCP server
#

runserver

#######################################################################
# The main test-loop
#

for NUMBER in $TESTCASES; do

  singletest $NUMBER

  # loop for next test
done

#######################################################################
# Tests done, stop server
#

stopserver
