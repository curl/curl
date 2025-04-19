#!/usr/bin/env bash
#***************************************************************************
#                                  _   _ ____  _
#  Project                     ___| | | |  _ \| |
#                             / __| | | | |_) | |
#                            | (__| |_| |  _ <| |___
#                             \___|\___/|_| \_\_____|
#
# Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
#
# This software is licensed as described in the file COPYING, which
# you should have received as part of this distribution. The terms
# are also available at https://curl.se/docs/copyright.html.
#
# You may opt to use, copy, modify, merge, publish, distribute and/or sell
# copies of the Software, and permit persons to whom the Software is
# furnished to do so, under the terms of the COPYING file.
#
# This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
# KIND, either express or implied.
#
# SPDX-License-Identifier: curl
#
###########################################################################
#

# Run some tests against servers we know to support ECH (CF, defo.ie, etc.).
# as well as some we know don't do ECH but have an HTTPS RR, and finally some
# for which neither is the case.

# TODO: Translate this into something that approximates a valid curl test:-)
# Should be useful though even before such translation and a pile less work
# to do this than that.  The pile of work required would include making an
# ECH-enabled server and a DoH server. For now, this is just run manually.
#

# set -x

# Exit with an error if there's an active ech stanza in ~/.curlrc
# as that'd likely skew some results (e.g. turning a fail into a
# success or vice versa)
: "${CURL_CFG_FILE=$HOME/.curlrc}"
active_ech=$(grep ech "$CURL_CFG_FILE" | grep -v "#.*ech")
if [[ "$active_ech" != "" ]]
then
    echo "You seem to have an active ECH setting in $CURL_CFG_FILE"
    echo "That might affect results so please remove that or comment"
    echo "it out - exiting."
    exit 1
fi


# Targets we expect to be ECH-enabled servers
# for which an HTTPS RR is published.
# structure is host:port mapped to pathname
# TODO: add negative tests for these
declare -A ech_targets=(
    [my-own.net]="ech-check.php"
    [my-own.net:8443]="ech-check.php"
    [defo.ie]="ech-check.php"
    [cover.defo.ie]=""
    [draft-13.esni.defo.ie:8413]="stats"
    [draft-13.esni.defo.ie:8414]="stats"
    [draft-13.esni.defo.ie:9413]=""
    [draft-13.esni.defo.ie:10413]=""
    [draft-13.esni.defo.ie:11413]=""
    [draft-13.esni.defo.ie:12413]=""
    [draft-13.esni.defo.ie:12414]=""
    [cloudflare-ech.com]="cdn-cgi/trace"
    [tls-ech.dev]=""
    # this one's gone away for now (possibly temporarily)
    # [epochbelt.com]=""
)

# Targets we expect not to be ECH-enabled servers
# but for which an HTTPS RR is published.
declare -A httpsrr_targets=(
    [ietf.org]=""
    [rte.ie]=""
)

# Targets we expect not to be ECH-enabled servers
# and for which no HTTPS RR is published.
declare -A neither_targets=(
    [www.tcd.ie]=""
    [jell.ie]=""
)

#
# Variables that can be over-ridden from environment
#

# Top of curl test tree, assume we're there
: "${CTOP:=.}"

# Place to put test log output
: "${LTOP:=$CTOP/tests/ech-log/}"

# Place to stash outputs when things go wrong
: "${BTOP:=$LTOP}"

# Time to wait for a remote access to work, 10 seconds
: "${tout:=10s}"

# Where we find OpenSSL .so's
: "${OSSL:=$HOME/code/openssl-local-inst}"

# Where we find wolfSSL .so's
: "${WSSL:=$HOME/code/wolfssl/inst/lib}"

# Where we find BoringSSL .so's
: "${BSSL:=$HOME/code/boringssl/inst/lib}"

# Where we send DoH queries when using kdig or curl
: "${DOHSERVER:=one.one.one.one}"
: "${DOHPATH:=dns-query}"

# Whether to send mail when bad things happen (mostly for cronjob)
: "${DOMAIL:=no}"

# Misc vars and functions

DEFPORT=443

function whenisitagain()
{
    /bin/date -u +%Y%m%d-%H%M%S
}

function fileage()
{
    echo $(($(date +%s) - $(date +%s -r "$1")))
}

function hostport2host()
{
    case $1 in
      *:*) host=${1%:*} port=${1##*:};;
        *) host=$1      port=$DEFPORT;;
    esac
    echo "$host"
}

function hostport2port()
{
    case $1 in
      *:*) host=${1%:*} port=${1##*:};;
        *) host=$1      port=$DEFPORT;;
    esac
    echo "$port"
}

function cli_test()
{
    # 1st param is target URL
    turl=$1
    # 2nd param is 0 if we expect curl to not work or 1 if we expect it
    # to have worked
    curl_winorlose=$2
    # 3rd param is 0 if we expect ECH to not work or 1 if we expect it
    # to have worked
    ech_winorlose=$3
    # remaining params are passed to command line
    # echparms=(${@:4})
    IFS=" " read -r -a echparms <<< "${@:4}"

    TMPF=$(mktemp)
    cmd="timeout $tout $CURL ${CURL_PARAMS[*]} ${echparms[*]} $turl >$TMPF 2>&1"
    echo "cli_test: $cmd " >> "$logfile"
    timeout "$tout" "$CURL" "${CURL_PARAMS[@]}" "${echparms[@]}" "$turl" >"$TMPF" 2>&1
    eres=$?
    if [[ "$eres" == "124" ]]
    then
        allgood="no"
        echo "cli_test: Timeout running $cmd"
        cat "$TMPF" >> "$logfile"
        echo "cli_test: Timeout running $cmd" >> "$logfile"
    fi
    if [[ "$eres" != "0" && "$curl_winorlose" == "1" ]]
    then
        allgood="no"
        echo "cli_test: curl failure running $cmd"
        cat "$TMPF" >> "$logfile"
        echo "cli_test: curl failure running $cmd" >> "$logfile"
    fi
    ech_success=$(grep -c "ECH: result: status is succeeded" "$TMPF")
    if [[ "$ech_success" == "$ech_winorlose" ]]
    then
        echo "cli_test ok for ${echparms[*]}"
    else
        allgood="no"
        echo "cli_test: ECH failure running $cmd"
        cat "$TMPF" >> "$logfile"
        echo "cli_test: ECH failure running $cmd" >> "$logfile"
    fi
    rm -f "$TMPF"
}

function get_ech_configlist()
{
    domain=$1
    ecl=$(dig +short https "$domain" | grep "ech=" | sed -e 's/^.*ech=//' | sed -e 's/ .*//')
    echo "$ecl"
}

# start of main script

# start by assuming we have nothing we need...
have_ossl="no"
have_wolf="no"
have_bssl="no"
using_ossl="no"
using_wolf="no"
using_bssl="no"
have_curl="no"
have_dig="no"
have_kdig="no"
have_presout="no"
have_portsblocked="no"

# setup logging
NOW=$(whenisitagain)
BINNAME=$(basename "$0" .sh)
if [ ! -d "$LTOP" ]
then
    mkdir -p "$LTOP"
fi
if [ ! -d "$LTOP" ]
then
    echo "Can't see $LTOP for logs - exiting"
    exit 1
fi
logfile=$LTOP/${BINNAME}_$NOW.log

echo "-----" > "$logfile"
echo "Running $0 at $NOW"  >> "$logfile"
echo "Running $0 at $NOW"

# check we have the binaries needed and which TLS library we'll be using
if [ -f "$OSSL"/libssl.so ]
then
    have_ossl="yes"
fi
if [ -f "$WSSL"/libwolfssl.so ]
then
    have_wolf="yes"
fi
if [ -f "$BSSL"/libssl.so ]
then
    have_bssl="yes"
fi
CURL="$CTOP/src/curl"
CURL_PARAMS=(-vvv --doh-url https://one.one.one.one/dns-query)
if [ -f "$CTOP"/src/curl ]
then
    have_curl="yes"
fi
ossl_cnt=$(LD_LIBRARY_PATH=$OSSL $CURL "${CURL_PARAMS[@]}" -V 2> /dev/null | grep -c OpenSSL)
if ((ossl_cnt == 1))
then
    using_ossl="yes"
    # setup access to our .so
    export LD_LIBRARY_PATH=$OSSL
fi
bssl_cnt=$(LD_LIBRARY_PATH=$BSSL $CURL "${CURL_PARAMS[@]}" -V 2> /dev/null | grep -c BoringSSL)
if ((bssl_cnt == 1))
then
    using_bssl="yes"
    # setup access to our .so
    export LD_LIBRARY_PATH=$BSSL
fi
wolf_cnt=$($CURL "${CURL_PARAMS[@]}" -V 2> /dev/null | grep -c wolfSSL)
if ((wolf_cnt == 1))
then
    using_wolf="yes"
    # for some reason curl+wolfSSL dislikes certs that are ok
    # for browsers, so we'll test using "insecure" mode (-k)
    # but that's ok here as we're only interested in ECH testing
    CURL_PARAMS+=(-k)
fi
# check if we have dig and it knows https or not
digcmd="dig +short"
wdig=$(type -p dig)
if [[ "$wdig" != "" ]]
then
    have_dig="yes"
fi
wkdig=$(type -p kdig)
if [[ "$wkdig" != "" ]]
then
    have_kdig="yes"
    digcmd="kdig @$DOHSERVER +https +short"
fi
# see if our dig version knows HTTPS
dout=$($digcmd https defo.ie)
if [[ $dout != "1 . "* ]]
then
    dout=$($digcmd -t TYPE65 defo.ie)
    if [[ $dout == "1 . "* ]]
    then
        # we're good
        have_presout="yes"
    fi
else
    have_presout="yes"
fi

# Check if ports other than 443 are blocked from this
# vantage point (I run tests in a n/w where that's
# sadly true sometimes;-)
# echo "Checking if ports other than 443 are maybe blocked"
not443testurl="https://draft-13.esni.defo.ie:9413/"
timeout "$tout" "$CURL" "${CURL_PARAMS[@]}" "$not443testurl" >/dev/null 2>&1
eres=$?
if [[ "$eres" == "124" ]]
then
    echo "Timeout running curl for $not443testurl" >> "$logfile"
    echo "Timeout running curl for $not443testurl"
    have_portsblocked="yes"
fi

{
    echo "have_ossl: $have_ossl"
    echo "have_wolf: $have_wolf"
    echo "have_bssl: $have_bssl"
    echo "using_ossl: $using_ossl"
    echo "using_wolf: $using_wolf"
    echo "using_bssl: $using_bssl"
    echo "have_curl: $have_curl"
    echo "have_dig: $have_dig"
    echo "have_kdig: $have_kdig"
    echo "have_presout: $have_presout"
    echo "have_portsblocked: $have_portsblocked"
} >> "$logfile"

echo "curl: have $have_curl, cURL command: |$CURL ${CURL_PARAMS[*]}|"
echo "ossl: have: $have_ossl, using: $using_ossl"
echo "wolf: have: $have_wolf, using: $using_wolf"
echo "bssl: have: $have_bssl, using: $using_bssl"
echo "dig: $have_dig, kdig: $have_kdig, HTTPS pres format: $have_presout"
echo "dig command: |$digcmd|"
echo "ports != 443 blocked: $have_portsblocked"

if [[ "$have_curl" == "no" ]]
then
    echo "Can't proceed without curl - exiting"
    exit 32
fi

allgood="yes"

skip="false"

if [[ "$skip" != "true" ]]
then

# basic ECH good/bad
for targ in "${!ech_targets[@]}"
do
    if [[ "$using_wolf" == "yes" ]]
    then
        case $targ in
            "draft-13.esni.defo.ie:8414" | "tls-ech.dev" | \
            "cloudflare-ech.com" | "epochbelt.com")
                echo "Skipping $targ 'cause wolf"; continue;;
            *)
                ;;
        esac
    fi
    host=$(hostport2host "$targ")
    port=$(hostport2port "$targ")
    if [[ "$port" != "443" && "$have_portsblocked" == "yes" ]]
    then
        echo "Skipping $targ as ports != 443 seem blocked"
        continue
    fi
    path=${ech_targets[$targ]}
    turl="https://$host:$port/$path"
    echo "ECH check for $turl"
    {
        echo ""
        echo "ECH check for $turl"
    } >> "$logfile"
    timeout "$tout" "$CURL" "${CURL_PARAMS[@]}" --ech hard "$turl" >> "$logfile" 2>&1
    eres=$?
    if [[ "$eres" == "124" ]]
    then
        allgood="no"
        {
            echo "Timeout for $turl"
            echo -e "\tTimeout for $turl"
            echo "Timeout running curl for $host:$port/$path"
        } >> "$logfile"
    fi
    if [[ "$eres" != "0" ]]
    then
        allgood="no"
        echo "Error ($eres) for $turl" >> "$logfile"
        echo -e "\tError ($eres) for $turl"
    fi
    echo "" >> "$logfile"
done

# check if public_name override works (OpenSSL only)
if [[ "$using_ossl" == "yes" ]]
then
    for targ in "${!ech_targets[@]}"
    do
        host=$(hostport2host "$targ")
        port=$(hostport2port "$targ")
        if [[ "$port" != "443" && "$have_portsblocked" == "yes" ]]
        then
            echo "Skipping $targ as ports != 443 seem blocked"
            continue
        fi
        if [[ "$host" == "cloudflare-ech.com" ]]
        then
            echo "Skipping $host as they've blocked PN override"
            continue
        fi
        path=${ech_targets[$targ]}
        turl="https://$host:$port/$path"
        echo "PN override check for $turl"
        {
            echo ""
            echo "PN override check for $turl"
        } >> "$logfile"
        timeout "$tout" "$CURL" "${CURL_PARAMS[@]}" --ech pn:override --ech hard "$turl" >> "$logfile" 2>&1
        eres=$?
        if [[ "$eres" == "124" ]]
        then
            allgood="no"
            {
                echo "Timeout for $turl"
                echo -e "\tTimeout for $turl"
                echo "Timeout running curl for $host:$port/$path"
            } >> "$logfile"
        fi
        if [[ "$eres" != "0" ]]
        then
            allgood="no"
            echo "PN override Error ($eres) for $turl" >> "$logfile"
            echo -e "\tPN override Error ($eres) for $turl"
        fi
        echo "" >> "$logfile"
    done
fi

for targ in "${!httpsrr_targets[@]}"
do
    host=$(hostport2host "$targ")
    port=$(hostport2port "$targ")
    if [[ "$port" != "443" && "$have_portsblocked" == "yes" ]]
    then
        echo "Skipping $targ as ports != 443 seem blocked"
        continue
    fi
    path=${httpsrr_targets[$targ]}
    turl="https://$host:$port/$path"
    echo "HTTPS RR but no ECHConfig check for $turl"
    {
        echo ""
        echo "HTTPS RR but no ECHConfig check for $turl"
    } >> "$logfile"
    timeout "$tout" "$CURL" "${CURL_PARAMS[@]}" --ech true "$turl" >> "$logfile" 2>&1
    eres=$?
    if [[ "$eres" == "124" ]]
    then
        allgood="no"
        {
            echo "Timeout for $turl"
            echo -e "\tTimeout for $turl"
            echo "Timeout running curl for $host:$port/$path"
        } >> "$logfile"
    fi
    if [[ "$eres" != "0" ]]
    then
        allgood="no"
        echo "Error ($eres) for $turl" >> "$logfile"
        echo -e "\tError ($eres) for $turl"
    fi
    echo "" >> "$logfile"
done

for targ in "${!neither_targets[@]}"
do
    host=$(hostport2host "$targ")
    port=$(hostport2port "$targ")
    if [[ "$port" != "443" && "$have_portsblocked" == "yes" ]]
    then
        echo "Skipping $targ as ports != 443 seem blocked"
        continue
    fi
    path=${neither_targets[$targ]}
    turl="https://$host:$port/$path"
    echo "Neither HTTPS nor ECHConfig check for $turl"
    {
        echo ""
        echo "Neither HTTPS nor ECHConfig check for $turl"
    } >> "$logfile"
    timeout "$tout" "$CURL" "${CURL_PARAMS[@]}" --ech true "$turl" >> "$logfile" 2>&1
    eres=$?
    if [[ "$eres" == "124" ]]
    then
        allgood="no"
        {
            echo "Timeout for $turl"
            echo -e "\tTimeout for $turl"
            echo "Timeout running curl for $host:$port/$path"
        } >> "$logfile"
    fi
    if [[ "$eres" != "0" ]]
    then
        allgood="no"
        echo "Error ($eres) for $turl" >> "$logfile"
        echo -e "\tError ($eres) for $turl"
    fi
    echo "" >> "$logfile"
done


# Check various command line options, if we're good so far
if [[ "$using_ossl" == "yes" && "$allgood" == "yes" ]]
then
    # use this test URL as it'll tell us if things worked
    turl="https://defo.ie/ech-check.php"
    echo "cli_test with $turl"
    echo "cli_test with $turl" >> "$logfile"
    cli_test "$turl" 1 1 --ech true
    cli_test "$turl" 1 0 --ech false
    cli_test "$turl" 1 1 --ech false --ech true
    cli_test "$turl" 1 1 --ech false --ech true --ech pn:foobar
    cli_test "$turl" 1 1 --ech false --ech pn:foobar --ech true
    echconfiglist=$(get_ech_configlist defo.ie)
    cli_test "$turl" 1 1 --ech ecl:"$echconfiglist"
    cli_test "$turl" 1 0 --ech ecl:
fi

fi # skip

# Check combinations of command line options, if we're good so far
# Most of this only works for OpenSSL, which is ok, as we're checking
# the argument handling here, not the ECH protocol
if [[ "$using_ossl" == "yes" && "$allgood" == "yes" ]]
then
    # ech can be hard, true, grease or false
    # ecl:ecl can be correct, incorrect or missing
    # ech:pn can be correct, incorrect or missing
    # in all cases the "last" argument provided should "win"
    # but only one of hard, true, grease or false will apply
    turl="https://defo.ie/ech-check.php"
    echconfiglist=$(get_ech_configlist defo.ie)
    goodecl=$echconfiglist
    echconfiglist=$(get_ech_configlist hidden.hoba.ie)
    badecl=$echconfiglist
    goodpn="cover.defo.ie"
    badpn="hoba.ie"
    echo "more cli_test with $turl"
    echo "more cli_test with $turl" >> "$logfile"

    # The combinatorics here are handled via the tests/ech_combos.py script
    # which produces all the relevant combinations or inputs and orders
    # thereof. We have to manually assess whether or not ECH is expected to
    # work for each case.
    cli_test "$turl" 0 0
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 0 0 --ech ecl:"$badecl"
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 1 1 --ech ecl:"$badecl" --ech ecl:"$goodecl"
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 1 1 --ech ecl:"$badecl" --ech ecl:"$goodecl" --ech pn:"$goodpn"
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 0 0 --ech ecl:"$badecl" --ech hard
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 1 1 --ech ecl:"$badecl" --ech hard --ech ecl:"$goodecl"
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 1 1 --ech ecl:"$badecl" --ech hard --ech ecl:"$goodecl" --ech pn:"$goodpn"
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 0 0 --ech ecl:"$badecl" --ech hard --ech pn:"$goodpn"
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 0 0 --ech ecl:"$badecl" --ech hard --ech true
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 1 1 --ech ecl:"$badecl" --ech hard --ech true --ech ecl:"$goodecl"
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 1 1 --ech ecl:"$badecl" --ech hard --ech true --ech ecl:"$goodecl" --ech pn:"$goodpn"
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 0 0 --ech ecl:"$badecl" --ech hard --ech true --ech pn:"$goodpn"
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 0 0 --ech ecl:"$badecl" --ech pn:"$badpn"
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 1 1 --ech ecl:"$badecl" --ech pn:"$badpn" --ech ecl:"$goodecl"
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 1 1 --ech ecl:"$badecl" --ech pn:"$badpn" --ech ecl:"$goodecl" --ech pn:"$goodpn"
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 0 0 --ech ecl:"$badecl" --ech pn:"$badpn" --ech hard
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 1 1 --ech ecl:"$badecl" --ech pn:"$badpn" --ech hard --ech ecl:"$goodecl"
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 1 1 --ech ecl:"$badecl" --ech pn:"$badpn" --ech hard --ech ecl:"$goodecl" --ech pn:"$goodpn"
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 0 0 --ech ecl:"$badecl" --ech pn:"$badpn" --ech hard --ech pn:"$goodpn"
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 0 0 --ech ecl:"$badecl" --ech pn:"$badpn" --ech hard --ech true
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 1 1 --ech ecl:"$badecl" --ech pn:"$badpn" --ech hard --ech true --ech ecl:"$goodecl"
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 1 1 --ech ecl:"$badecl" --ech pn:"$badpn" --ech hard --ech true --ech ecl:"$goodecl" --ech pn:"$goodpn"
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 0 0 --ech ecl:"$badecl" --ech pn:"$badpn" --ech hard --ech true --ech pn:"$goodpn"
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 0 0 --ech ecl:"$badecl" --ech pn:"$badpn" --ech pn:"$goodpn"
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 0 0 --ech ecl:"$badecl" --ech pn:"$badpn" --ech true
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 1 1 --ech ecl:"$badecl" --ech pn:"$badpn" --ech true --ech ecl:"$goodecl"
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 1 1 --ech ecl:"$badecl" --ech pn:"$badpn" --ech true --ech ecl:"$goodecl" --ech pn:"$goodpn"
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" - 0 --ech ecl:"$badecl" --ech pn:"$badpn" --ech true --ech pn:"$goodpn"
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 0 0 --ech ecl:"$badecl" --ech pn:"$goodpn"
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 0 0 --ech ecl:"$badecl" --ech true
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 1 1 --ech ecl:"$badecl" --ech true --ech ecl:"$goodecl"
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 1 1 --ech ecl:"$badecl" --ech true --ech ecl:"$goodecl" --ech pn:"$goodpn"
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 0 0 --ech ecl:"$badecl" --ech true --ech pn:"$goodpn"
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 1 1 --ech ecl:"$goodecl"
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 1 1 --ech ecl:"$goodecl" --ech pn:"$goodpn"
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 1 0 --ech false
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 1 0 --ech false --ech ecl:"$badecl"
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 1 0 --ech false --ech ecl:"$badecl" --ech ecl:"$goodecl"
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 1 0 --ech false --ech ecl:"$badecl" --ech ecl:"$goodecl" --ech pn:"$goodpn"
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 0 0 --ech false --ech ecl:"$badecl" --ech hard
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 1 1 --ech false --ech ecl:"$badecl" --ech hard --ech ecl:"$goodecl"
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 1 1 --ech false --ech ecl:"$badecl" --ech hard --ech ecl:"$goodecl" --ech pn:"$goodpn"
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 0 0 --ech false --ech ecl:"$badecl" --ech hard --ech pn:"$goodpn"
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 0 0 --ech false --ech ecl:"$badecl" --ech hard --ech true
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 1 1 --ech false --ech ecl:"$badecl" --ech hard --ech true --ech ecl:"$goodecl"
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 1 1 --ech false --ech ecl:"$badecl" --ech hard --ech true --ech ecl:"$goodecl" --ech pn:"$goodpn"
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 0 0 --ech false --ech ecl:"$badecl" --ech hard --ech true --ech pn:"$goodpn"
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 1 0 --ech false --ech ecl:"$badecl" --ech pn:"$badpn"
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 1 0 --ech false --ech ecl:"$badecl" --ech pn:"$badpn" --ech ecl:"$goodecl"
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 1 0 --ech false --ech ecl:"$badecl" --ech pn:"$badpn" --ech ecl:"$goodecl" --ech pn:"$goodpn"
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 0 0 --ech false --ech ecl:"$badecl" --ech pn:"$badpn" --ech hard
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 1 1 --ech false --ech ecl:"$badecl" --ech pn:"$badpn" --ech hard --ech ecl:"$goodecl"
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 1 1 --ech false --ech ecl:"$badecl" --ech pn:"$badpn" --ech hard --ech ecl:"$goodecl" --ech pn:"$goodpn"
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 0 0 --ech false --ech ecl:"$badecl" --ech pn:"$badpn" --ech hard --ech pn:"$goodpn"
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 0 0 --ech false --ech ecl:"$badecl" --ech pn:"$badpn" --ech hard --ech true
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 1 1 --ech false --ech ecl:"$badecl" --ech pn:"$badpn" --ech hard --ech true --ech ecl:"$goodecl"
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 1 1 --ech false --ech ecl:"$badecl" --ech pn:"$badpn" --ech hard --ech true --ech ecl:"$goodecl" --ech pn:"$goodpn"
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 0 0 --ech false --ech ecl:"$badecl" --ech pn:"$badpn" --ech hard --ech true --ech pn:"$goodpn"
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 1 0 --ech false --ech ecl:"$badecl" --ech pn:"$badpn" --ech pn:"$goodpn"
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 0 0 --ech false --ech ecl:"$badecl" --ech pn:"$badpn" --ech true
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 1 1 --ech false --ech ecl:"$badecl" --ech pn:"$badpn" --ech true --ech ecl:"$goodecl"
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 1 1 --ech false --ech ecl:"$badecl" --ech pn:"$badpn" --ech true --ech ecl:"$goodecl" --ech pn:"$goodpn"
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 0 0 --ech false --ech ecl:"$badecl" --ech pn:"$badpn" --ech true --ech pn:"$goodpn"
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 1 0 --ech false --ech ecl:"$badecl" --ech pn:"$goodpn"
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 0 0 --ech false --ech ecl:"$badecl" --ech true
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 1 1 --ech false --ech ecl:"$badecl" --ech true --ech ecl:"$goodecl"
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 1 1 --ech false --ech ecl:"$badecl" --ech true --ech ecl:"$goodecl" --ech pn:"$goodpn"
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 0 0 --ech false --ech ecl:"$badecl" --ech true --ech pn:"$goodpn"
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 1 0 --ech false --ech ecl:"$goodecl"
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 1 0 --ech false --ech ecl:"$goodecl" --ech pn:"$goodpn"
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 1 1 --ech false --ech hard
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 1 1 --ech false --ech hard --ech ecl:"$goodecl"
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 1 1 --ech false --ech hard --ech ecl:"$goodecl" --ech pn:"$goodpn"
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 1 1 --ech false --ech hard --ech pn:"$goodpn"
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 1 1 --ech false --ech hard --ech true
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 1 1 --ech false --ech hard --ech true --ech ecl:"$goodecl"
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 1 1 --ech false --ech hard --ech true --ech ecl:"$goodecl" --ech pn:"$goodpn"
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 1 1 --ech false --ech hard --ech true --ech pn:"$goodpn"
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 1 0 --ech false --ech pn:"$badpn"
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 1 0 --ech false --ech pn:"$badpn" --ech ecl:"$goodecl"
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 1 0 --ech false --ech pn:"$badpn" --ech ecl:"$goodecl" --ech pn:"$goodpn"
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 1 1 --ech false --ech pn:"$badpn" --ech hard
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 1 1 --ech false --ech pn:"$badpn" --ech hard --ech ecl:"$goodecl"
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 1 1 --ech false --ech pn:"$badpn" --ech hard --ech ecl:"$goodecl" --ech pn:"$goodpn"
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 1 1 --ech false --ech pn:"$badpn" --ech hard --ech pn:"$goodpn"
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 1 1 --ech false --ech pn:"$badpn" --ech hard --ech true
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 1 1 --ech false --ech pn:"$badpn" --ech hard --ech true --ech ecl:"$goodecl"
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 1 1 --ech false --ech pn:"$badpn" --ech hard --ech true --ech ecl:"$goodecl" --ech pn:"$goodpn"
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 1 1 --ech false --ech pn:"$badpn" --ech hard --ech true --ech pn:"$goodpn"
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 1 0 --ech false --ech pn:"$badpn" --ech pn:"$goodpn"
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 1 1 --ech false --ech pn:"$badpn" --ech true
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 1 1 --ech false --ech pn:"$badpn" --ech true --ech ecl:"$goodecl"
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 1 1 --ech false --ech pn:"$badpn" --ech true --ech ecl:"$goodecl" --ech pn:"$goodpn"
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 1 1 --ech false --ech pn:"$badpn" --ech true --ech pn:"$goodpn"
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 1 0 --ech false --ech pn:"$goodpn"
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 1 1 --ech false --ech true
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 1 1 --ech false --ech true --ech ecl:"$goodecl"
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 1 1 --ech false --ech true --ech ecl:"$goodecl" --ech pn:"$goodpn"
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 1 1 --ech false --ech true --ech pn:"$goodpn"
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 1 1 --ech hard
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 1 1 --ech hard --ech ecl:"$goodecl"
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 1 1 --ech hard --ech ecl:"$goodecl" --ech pn:"$goodpn"
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 1 1 --ech hard --ech pn:"$goodpn"
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 1 1 --ech hard --ech true
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 1 1 --ech hard --ech true --ech ecl:"$goodecl"
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 1 1 --ech hard --ech true --ech ecl:"$goodecl" --ech pn:"$goodpn"
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 1 1 --ech hard --ech true --ech pn:"$goodpn"
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 1 0 --ech pn:"$badpn"
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 1 1 --ech pn:"$badpn" --ech ecl:"$goodecl"
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 1 1 --ech pn:"$badpn" --ech ecl:"$goodecl" --ech pn:"$goodpn"
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 1 1 --ech pn:"$badpn" --ech hard
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 1 1 --ech pn:"$badpn" --ech hard --ech ecl:"$goodecl"
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 1 1 --ech pn:"$badpn" --ech hard --ech ecl:"$goodecl" --ech pn:"$goodpn"
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 1 1 --ech pn:"$badpn" --ech hard --ech pn:"$goodpn"
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 1 1 --ech pn:"$badpn" --ech hard --ech true
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 1 1 --ech pn:"$badpn" --ech hard --ech true --ech ecl:"$goodecl"
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 1 1 --ech pn:"$badpn" --ech hard --ech true --ech ecl:"$goodecl" --ech pn:"$goodpn"
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 1 1 --ech pn:"$badpn" --ech hard --ech true --ech pn:"$goodpn"
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 1 0 --ech pn:"$badpn" --ech pn:"$goodpn"
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 1 1 --ech pn:"$badpn" --ech true
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 1 1 --ech pn:"$badpn" --ech true --ech ecl:"$goodecl"
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 1 1 --ech pn:"$badpn" --ech true --ech ecl:"$goodecl" --ech pn:"$goodpn"
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 1 1 --ech pn:"$badpn" --ech true --ech pn:"$goodpn"
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 1 0 --ech pn:"$goodpn"
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 1 1 --ech true
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 1 1 --ech true --ech ecl:"$goodecl"
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 1 1 --ech true --ech ecl:"$goodecl" --ech pn:"$goodpn"
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 1 1 --ech true --ech pn:"$goodpn"
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 1 0
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 1 1 --ech ecl:"$goodecl"
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 1 1 --ech ecl:"$goodecl" --ech pn:"$goodpn"
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 1 0 --ech pn:"$goodpn"
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 1 1 --ech true
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 1 1 --ech true --ech ecl:"$goodecl"
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 1 1 --ech true --ech ecl:"$goodecl" --ech pn:"$goodpn"
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 1 1 --ech true --ech pn:"$goodpn"
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi

    # a target URL that doesn't support ECH
    turl="https://tcd.ie"
    echo "cli_test with $turl"
    echo "cli_test with $turl" >> "$logfile"
    # the params below don't matter much here as we'll fail anyway
    echconfiglist=$(get_ech_configlist defo.ie)
    goodecl=$echconfiglist
    badecl="$goodecl"
    goodpn="tcd.ie"
    badpn="tcd.ie"
    cli_test "$turl" 1 0
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 0 0 --ech ecl:"$badecl"
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 0 0 --ech ecl:"$badecl" --ech ecl:"$goodecl"
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 0 0 --ech ecl:"$badecl" --ech ecl:"$goodecl" --ech pn:"$goodpn"
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 0 0 --ech ecl:"$badecl" --ech hard
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 0 0 --ech ecl:"$badecl" --ech hard --ech ecl:"$goodecl"
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 0 0 --ech ecl:"$badecl" --ech hard --ech ecl:"$goodecl" --ech pn:"$goodpn"
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 0 0 --ech ecl:"$badecl" --ech hard --ech pn:"$goodpn"
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 0 0 --ech ecl:"$badecl" --ech hard --ech true
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 0 0 --ech ecl:"$badecl" --ech hard --ech true --ech ecl:"$goodecl"
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 0 0 --ech ecl:"$badecl" --ech hard --ech true --ech ecl:"$goodecl" --ech pn:"$goodpn"
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 0 0 --ech ecl:"$badecl" --ech hard --ech true --ech pn:"$goodpn"
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 0 0 --ech ecl:"$badecl" --ech pn:"$badpn"
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 0 0 --ech ecl:"$badecl" --ech pn:"$badpn" --ech ecl:"$goodecl"
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 0 0 --ech ecl:"$badecl" --ech pn:"$badpn" --ech ecl:"$goodecl" --ech pn:"$goodpn"
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 0 0 --ech ecl:"$badecl" --ech pn:"$badpn" --ech hard
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 0 0 --ech ecl:"$badecl" --ech pn:"$badpn" --ech hard --ech ecl:"$goodecl"
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 0 0 --ech ecl:"$badecl" --ech pn:"$badpn" --ech hard --ech ecl:"$goodecl" --ech pn:"$goodpn"
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 0 0 --ech ecl:"$badecl" --ech pn:"$badpn" --ech hard --ech pn:"$goodpn"
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 0 0 --ech ecl:"$badecl" --ech pn:"$badpn" --ech hard --ech true
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 0 0 --ech ecl:"$badecl" --ech pn:"$badpn" --ech hard --ech true --ech ecl:"$goodecl"
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 0 0 --ech ecl:"$badecl" --ech pn:"$badpn" --ech hard --ech true --ech ecl:"$goodecl" --ech pn:"$goodpn"
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 0 0 --ech ecl:"$badecl" --ech pn:"$badpn" --ech hard --ech true --ech pn:"$goodpn"
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 0 0 --ech ecl:"$badecl" --ech pn:"$badpn" --ech pn:"$goodpn"
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 0 0 --ech ecl:"$badecl" --ech pn:"$badpn" --ech true
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 0 0 --ech ecl:"$badecl" --ech pn:"$badpn" --ech true --ech ecl:"$goodecl"
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 0 0 --ech ecl:"$badecl" --ech pn:"$badpn" --ech true --ech ecl:"$goodecl" --ech pn:"$goodpn"
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 0 0 --ech ecl:"$badecl" --ech pn:"$badpn" --ech true --ech pn:"$goodpn"
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 0 0 --ech ecl:"$badecl" --ech pn:"$goodpn"
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 0 0 --ech ecl:"$badecl" --ech true
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 0 0 --ech ecl:"$badecl" --ech true --ech ecl:"$goodecl"
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 0 0 --ech ecl:"$badecl" --ech true --ech ecl:"$goodecl" --ech pn:"$goodpn"
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 0 0 --ech ecl:"$badecl" --ech true --ech pn:"$goodpn"
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 0 0 --ech ecl:"$goodecl"
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 0 0 --ech ecl:"$goodecl" --ech pn:"$goodpn"
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 0 0 --ech false
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 0 0 --ech false --ech ecl:"$badecl"
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 0 0 --ech false --ech ecl:"$badecl" --ech ecl:"$goodecl"
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 0 0 --ech false --ech ecl:"$badecl" --ech ecl:"$goodecl" --ech pn:"$goodpn"
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 0 0 --ech false --ech ecl:"$badecl" --ech hard
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 0 0 --ech false --ech ecl:"$badecl" --ech hard --ech ecl:"$goodecl"
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 0 0 --ech false --ech ecl:"$badecl" --ech hard --ech ecl:"$goodecl" --ech pn:"$goodpn"
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 0 0 --ech false --ech ecl:"$badecl" --ech hard --ech pn:"$goodpn"
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 0 0 --ech false --ech ecl:"$badecl" --ech hard --ech true
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 0 0 --ech false --ech ecl:"$badecl" --ech hard --ech true --ech ecl:"$goodecl"
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 0 0 --ech false --ech ecl:"$badecl" --ech hard --ech true --ech ecl:"$goodecl" --ech pn:"$goodpn"
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 0 0 --ech false --ech ecl:"$badecl" --ech hard --ech true --ech pn:"$goodpn"
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 0 0 --ech false --ech ecl:"$badecl" --ech pn:"$badpn"
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 0 0 --ech false --ech ecl:"$badecl" --ech pn:"$badpn" --ech ecl:"$goodecl"
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 0 0 --ech false --ech ecl:"$badecl" --ech pn:"$badpn" --ech ecl:"$goodecl" --ech pn:"$goodpn"
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 0 0 --ech false --ech ecl:"$badecl" --ech pn:"$badpn" --ech hard
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 0 0 --ech false --ech ecl:"$badecl" --ech pn:"$badpn" --ech hard --ech ecl:"$goodecl"
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 0 0 --ech false --ech ecl:"$badecl" --ech pn:"$badpn" --ech hard --ech ecl:"$goodecl" --ech pn:"$goodpn"
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 0 0 --ech false --ech ecl:"$badecl" --ech pn:"$badpn" --ech hard --ech pn:"$goodpn"
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 0 0 --ech false --ech ecl:"$badecl" --ech pn:"$badpn" --ech hard --ech true
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 0 0 --ech false --ech ecl:"$badecl" --ech pn:"$badpn" --ech hard --ech true --ech ecl:"$goodecl"
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 0 0 --ech false --ech ecl:"$badecl" --ech pn:"$badpn" --ech hard --ech true --ech ecl:"$goodecl" --ech pn:"$goodpn"
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 0 0 --ech false --ech ecl:"$badecl" --ech pn:"$badpn" --ech hard --ech true --ech pn:"$goodpn"
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 0 0 --ech false --ech ecl:"$badecl" --ech pn:"$badpn" --ech pn:"$goodpn"
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 0 0 --ech false --ech ecl:"$badecl" --ech pn:"$badpn" --ech true
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 0 0 --ech false --ech ecl:"$badecl" --ech pn:"$badpn" --ech true --ech ecl:"$goodecl"
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 0 0 --ech false --ech ecl:"$badecl" --ech pn:"$badpn" --ech true --ech ecl:"$goodecl" --ech pn:"$goodpn"
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 0 0 --ech false --ech ecl:"$badecl" --ech pn:"$badpn" --ech true --ech pn:"$goodpn"
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 0 0 --ech false --ech ecl:"$badecl" --ech pn:"$goodpn"
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 0 0 --ech false --ech ecl:"$badecl" --ech true
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 0 0 --ech false --ech ecl:"$badecl" --ech true --ech ecl:"$goodecl"
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 0 0 --ech false --ech ecl:"$badecl" --ech true --ech ecl:"$goodecl" --ech pn:"$goodpn"
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 0 0 --ech false --ech ecl:"$badecl" --ech true --ech pn:"$goodpn"
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 0 0 --ech false --ech ecl:"$goodecl"
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 0 0 --ech false --ech ecl:"$goodecl" --ech pn:"$goodpn"
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 0 0 --ech false --ech hard
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 0 0 --ech false --ech hard --ech ecl:"$goodecl"
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 0 0 --ech false --ech hard --ech ecl:"$goodecl" --ech pn:"$goodpn"
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 0 0 --ech false --ech hard --ech pn:"$goodpn"
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 0 0 --ech false --ech hard --ech true
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 0 0 --ech false --ech hard --ech true --ech ecl:"$goodecl"
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 0 0 --ech false --ech hard --ech true --ech ecl:"$goodecl" --ech pn:"$goodpn"
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 0 0 --ech false --ech hard --ech true --ech pn:"$goodpn"
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 0 0 --ech false --ech pn:"$badpn"
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 0 0 --ech false --ech pn:"$badpn" --ech ecl:"$goodecl"
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 0 0 --ech false --ech pn:"$badpn" --ech ecl:"$goodecl" --ech pn:"$goodpn"
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 0 0 --ech false --ech pn:"$badpn" --ech hard
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 0 0 --ech false --ech pn:"$badpn" --ech hard --ech ecl:"$goodecl"
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 0 0 --ech false --ech pn:"$badpn" --ech hard --ech ecl:"$goodecl" --ech pn:"$goodpn"
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 0 0 --ech false --ech pn:"$badpn" --ech hard --ech pn:"$goodpn"
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 0 0 --ech false --ech pn:"$badpn" --ech hard --ech true
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 0 0 --ech false --ech pn:"$badpn" --ech hard --ech true --ech ecl:"$goodecl"
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 0 0 --ech false --ech pn:"$badpn" --ech hard --ech true --ech ecl:"$goodecl" --ech pn:"$goodpn"
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 0 0 --ech false --ech pn:"$badpn" --ech hard --ech true --ech pn:"$goodpn"
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 0 0 --ech false --ech pn:"$badpn" --ech pn:"$goodpn"
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 0 0 --ech false --ech pn:"$badpn" --ech true
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 0 0 --ech false --ech pn:"$badpn" --ech true --ech ecl:"$goodecl"
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 0 0 --ech false --ech pn:"$badpn" --ech true --ech ecl:"$goodecl" --ech pn:"$goodpn"
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 0 0 --ech false --ech pn:"$badpn" --ech true --ech pn:"$goodpn"
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 0 0 --ech false --ech pn:"$goodpn"
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 0 0 --ech false --ech true
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 0 0 --ech false --ech true --ech ecl:"$goodecl"
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 0 0 --ech false --ech true --ech ecl:"$goodecl" --ech pn:"$goodpn"
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 0 0 --ech false --ech true --ech pn:"$goodpn"
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 0 0 --ech hard
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 0 0 --ech hard --ech ecl:"$goodecl"
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 0 0 --ech hard --ech ecl:"$goodecl" --ech pn:"$goodpn"
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 0 0 --ech hard --ech pn:"$goodpn"
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 0 0 --ech hard --ech true
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 0 0 --ech hard --ech true --ech ecl:"$goodecl"
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 0 0 --ech hard --ech true --ech ecl:"$goodecl" --ech pn:"$goodpn"
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 0 0 --ech hard --ech true --ech pn:"$goodpn"
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 0 0 --ech pn:"$badpn"
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 0 0 --ech pn:"$badpn" --ech ecl:"$goodecl"
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 0 0 --ech pn:"$badpn" --ech ecl:"$goodecl" --ech pn:"$goodpn"
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 0 0 --ech pn:"$badpn" --ech hard
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 0 0 --ech pn:"$badpn" --ech hard --ech ecl:"$goodecl"
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 0 0 --ech pn:"$badpn" --ech hard --ech ecl:"$goodecl" --ech pn:"$goodpn"
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 0 0 --ech pn:"$badpn" --ech hard --ech pn:"$goodpn"
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 0 0 --ech pn:"$badpn" --ech hard --ech true
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 0 0 --ech pn:"$badpn" --ech hard --ech true --ech ecl:"$goodecl"
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 0 0 --ech pn:"$badpn" --ech hard --ech true --ech ecl:"$goodecl" --ech pn:"$goodpn"
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 0 0 --ech pn:"$badpn" --ech hard --ech true --ech pn:"$goodpn"
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 0 0 --ech pn:"$badpn" --ech pn:"$goodpn"
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 0 0 --ech pn:"$badpn" --ech true
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 0 0 --ech pn:"$badpn" --ech true --ech ecl:"$goodecl"
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 0 0 --ech pn:"$badpn" --ech true --ech ecl:"$goodecl" --ech pn:"$goodpn"
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 0 0 --ech pn:"$badpn" --ech true --ech pn:"$goodpn"
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 0 0 --ech pn:"$goodpn"
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 0 0 --ech true
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 0 0 --ech true --ech ecl:"$goodecl"
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 0 0 --ech true --ech ecl:"$goodecl" --ech pn:"$goodpn"
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 0 0 --ech true --ech pn:"$goodpn"
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 0 0
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 0 0 --ech ecl:"$goodecl"
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 0 0 --ech ecl:"$goodecl" --ech pn:"$goodpn"
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 0 0 --ech pn:"$goodpn"
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 0 0 --ech true
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 0 0 --ech true --ech ecl:"$goodecl"
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 0 0 --ech true --ech ecl:"$goodecl" --ech pn:"$goodpn"
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
    cli_test "$turl" 0 0 --ech true --ech pn:"$goodpn"
    if [[ "$allgood" != "yes" ]]; then echo "$LINENO"; fi
fi


END=$(whenisitagain)
echo "Finished $0 at $END"  >> "$logfile"
echo "-----" >> "$logfile"

if [[ "$allgood" == "yes" ]]
then
    echo "Finished $0 at $END"
    echo "All good, log in $logfile"
    exit 0
else
    echo "Finished $0 at $END"
    echo "NOT all good, log in $logfile"
fi

# send a mail to root (will be fwd'd) but just once every 24 hours
# 'cause we only really need "new" news
itsnews="yes"
age_of_news=0
if [ -f "$LTOP"/bad_runs ]
then
    age_of_news=$(fileage "$LTOP"/bad_runs)
    # only consider news "new" if we haven't mailed today
    if ((age_of_news < 24*3600))
    then
        itsnews="no"
    fi
fi
if [[ "$DOMAIL" == "yes" && "$itsnews" == "yes" ]]
then
    echo "ECH badness at $NOW" | mail -s "ECH badness at $NOW" root
fi
# add to list of bad runs (updating file age)
echo "ECH badness at $NOW" >>"$LTOP"/bad_runs
exit 2
