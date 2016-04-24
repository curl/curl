#!/bin/sh
# ***************************************************************************
# *                                  _   _ ____  _
# *  Project                     ___| | | |  _ \| |
# *                             / __| | | | |_) | |
# *                            | (__| |_| |  _ <| |___
# *                             \___|\___/|_| \_\_____|
# *
# * Copyright (C) 2013, Daniel Stenberg, <daniel@haxx.se>, et al.
# *
# * This software is licensed as described in the file COPYING, which
# * you should have received as part of this distribution. The terms
# * are also available at https://curl.haxx.se/docs/copyright.html.
# *
# * You may opt to use, copy, modify, merge, publish, distribute and/or sell
# * copies of the Software, and permit persons to whom the Software is
# * furnished to do so, under the terms of the COPYING file.
# *
# * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
# * KIND, either express or implied.
# *
# ***************************************************************************

#
# This Bourne shell script file is used by test case 1222 to do
# unit testing of curl_8char_object_name() shell function which
# is defined in file objnames.inc and sourced by this file and
# any other shell script that may use it.
#

#
# argument validation
#

if test $# -eq 1; then
  :
else
  echo "Usage: ${0} srcdir"
  exit 1
fi

if test -f "${1}/runtests.pl"; then
  :
else
  echo "${0}: Wrong srcdir"
  exit 1
fi

srcdir=${1}

if test -f "$srcdir/../lib/objnames.inc"; then
  :
else
  echo "$0: Missing objnames.inc"
  exit 1
fi

#
# Some variables
#

logdir=log
tstnum=1222

list_c=$logdir/${tstnum}_list_c
list_obj=$logdir/${tstnum}_list_obj
list_obj_c=$logdir/${tstnum}_list_obj_c
list_obj_uniq=$logdir/${tstnum}_list_obj_uniq


#
# Source curl_8char_object_name() function definition
#

. $srcdir/../lib/objnames.inc

#
# Some curl_8char_object_name() unit tests
#

echo 'Testing curl_8char_object_name...'
echo ""

argstr=123__678__ABC__FGH__KLM__PQRSTUV
expect=16AFKPQR
outstr=`curl_8char_object_name $argstr`
echo "result: $outstr expected: $expect input: $argstr"

argstr=123__678__ABC__FGH__KLM__PQ.S.UV
expect=16AFKPQ
outstr=`curl_8char_object_name $argstr`
echo "result: $outstr expected: $expect input: $argstr"

argstr=123__678__ABC..FGH..KLM..PQRSTUV
expect=16ABC
outstr=`curl_8char_object_name $argstr`
echo "result: $outstr expected: $expect input: $argstr"

argstr=123__678_.ABC._FGH__KLM__PQRSTUV
expect=16
outstr=`curl_8char_object_name $argstr`
echo "result: $outstr expected: $expect input: $argstr"

argstr=123.567.90ABCDEFGHIJKLMNOPQRSTUV
expect=123
outstr=`curl_8char_object_name $argstr`
echo "result: $outstr expected: $expect input: $argstr"

argstr=1234567.90A.CDEFGHIJKLMNOPQRSTUV
expect=1234567
outstr=`curl_8char_object_name $argstr`
echo "result: $outstr expected: $expect input: $argstr"

argstr=1234567890.BCD.FGHIJKLMNOPQRSTUV
expect=12345678
outstr=`curl_8char_object_name $argstr`
echo "result: $outstr expected: $expect input: $argstr"

argstr=12=45-78+0AB.DE.GHIJKLMNOPQRSTUV
expect=1470AB
outstr=`curl_8char_object_name $argstr`
echo "result: $outstr expected: $expect input: $argstr"

argstr=1234567890ABCDEFGHIJKLMNOPQRSTUV
expect=12345678
outstr=`curl_8char_object_name $argstr`
echo "result: $outstr expected: $expect input: $argstr"

argstr=123_567_90A_CDE_GHIJKLMNOPQRSTUV
expect=159CGHIJ
outstr=`curl_8char_object_name $argstr`
echo "result: $outstr expected: $expect input: $argstr"

argstr=123_567_90A_CDEFGHIJKLMNOPQRSTUV
expect=159CDEFG
outstr=`curl_8char_object_name $argstr`
echo "result: $outstr expected: $expect input: $argstr"

argstr=123_567_90ABCDEFGHIJKLMNOPQRSTUV
expect=1590ABCD
outstr=`curl_8char_object_name $argstr`
echo "result: $outstr expected: $expect input: $argstr"

argstr=123_567890ABCDEFGHIJKLMNOPQRSTUV
expect=1567890A
outstr=`curl_8char_object_name $argstr`
echo "result: $outstr expected: $expect input: $argstr"

argstr=1234567890ABCDEFGHIJKLMNOPQRSTUV
expect=12345678
outstr=`curl_8char_object_name $argstr`
echo "result: $outstr expected: $expect input: $argstr"

#
# Verify that generated object name is distinct for
# all *.c source files in lib and src subdirectories.
#

ls $srcdir/../lib/*.c > $list_c
ls $srcdir/../src/*.c >> $list_c

rm -f $list_obj

for c_fname in `cat $list_c`; do
  obj_name=`curl_8char_object_name $c_fname`
  echo "$obj_name" >> $list_obj
done

sort -u $list_obj > $list_obj_uniq

cnt_c=`cat $list_c | wc -l`
cnt_u=`cat $list_obj_uniq | wc -l`

echo ""
echo ""
echo ""
if test $cnt_c -eq $cnt_u; then
  echo "8-characters-or-less generated object names are unique."
  obj_name_clash="no"
else
  echo "8-characters-or-less generated object names are clashing..."
  obj_name_clash="yes"
fi

if test $obj_name_clash = "yes"; then
  #
  # Show clashing object names and respective source file names
  #
  echo ""
  paste $list_obj $list_c | sort > $list_obj_c
  prev_match="no"
  prev_line="unknown"
  prev_obj_name="unknown"
  while read this_line; do
    obj_name=`echo "$this_line" | cut -f1`
    if test "x$obj_name" = "x$prev_obj_name"; then
      if test "x$prev_match" != "xyes"; then
        echo "$prev_line"
        echo "$this_line"
        prev_match="yes"
      else
        echo "$this_line"
      fi
    else
      prev_match="no"
    fi
    prev_line=$this_line
    prev_obj_name=$obj_name
  done < $list_obj_c
fi

rm -f $list_c
rm -f $list_obj
rm -f $list_obj_c
rm -f $list_obj_uniq

# end of objnames-test.sh
