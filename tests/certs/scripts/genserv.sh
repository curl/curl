#!/bin/bash

# (c) CopyRight EdelWeb for EdelKey and OpenEvidence, 2000-2004, 2009
# Author: Peter Sylvester

# "libre" for integration with curl 

OPENSSL=openssl
if [ -f /usr/local/ssl/bin/openssl ] ; then
   OPENSSL=/usr/local/ssl/bin/openssl
fi

USAGE="echo Usage is genserv.sh <prefix> <caprefix>"

HOME=`pwd`
cd $HOME

KEYSIZE=1024
DURATION=3000

REQ=YES
P12=NO
DHP=NO

PREFIX=$1
if [ ".$PREFIX" = . ] ; then
	echo No configuration prefix
	NOTOK=1
else
    if [ ! -f $PREFIX-sv.prm ] ; then
	echo No configuration file $PREFIX-sv.prm
	NOTOK=1
    fi
fi

CAPREFIX=$2
if [ ".$CAPREFIX" = . ] ; then
	echo No CA prefix
	NOTOK=1
else
    if [ ! -f $CAPREFIX-ca.cacert ] ; then
	echo No CA certficate file $PREFIX-ca.caert
	NOTOK=1
    fi
    if [ ! -f $CAPREFIX-ca.key ] ; then
	echo No $CAPREFIX key
        NOTOK=1
    fi
fi

if [ ".$NOTOK" != . ] ; then
    echo "Sorry, I can't do that for you."
    $USAGE
    exit
fi

if [ ".$SERIAL" = . ] ; then
	GETSERIAL="\$t = time ;\$d =  \$t . substr(\$t+$$ ,-4,4)-1;print \$d"
	SERIAL=`/usr/bin/env perl -e "$GETSERIAL"`
fi

echo SERIAL=$SERIAL PREFIX=$PREFIX CAPREFIX=$CAPREFIX DURATION=$DURATION KEYSIZE=$KEYSIZE 

if [ "$DHP." = YES. ] ; then
   echo "openssl dhparam -2 -out $PREFIX-sv.dhp $KEYSIZE"
   $OPENSSL dhparam -2 -out $PREFIX-sv.dhp $KEYSIZE
fi

if [ "$REQ." = YES. ] ; then
   echo "openssl req -config $PREFIX-sv.prm -newkey rsa:$KEYSIZE -keyout $PREFIX-sv.key -out $PREFIX-sv.csr -passout XXX"
   $OPENSSL req -config $PREFIX-sv.prm -newkey rsa:$KEYSIZE -keyout $PREFIX-sv.key -out $PREFIX-sv.csr -passout pass:secret
fi

echo "openssl rsa -in $PREFIX-sv.key -out $PREFIX-sv.key"
$OPENSSL rsa -in $PREFIX-sv.key -out $PREFIX-sv.key -passin pass:secret 
echo pseudo secrets generated
read

echo "openssl x509 -set_serial $SERIAL -extfile $PREFIX-sv.prm -days $DURATION  -CA $CAPREFIX-ca.cacert -CAkey $CAPREFIX-ca.key -in $PREFIX-sv.csr -req -out $PREFIX-sv.crt -text -nameopt multiline -sha1"

$OPENSSL x509 -set_serial $SERIAL -extfile $PREFIX-sv.prm -days $DURATION  -CA $CAPREFIX-ca.cacert -CAkey $CAPREFIX-ca.key -in $PREFIX-sv.csr -req -out $PREFIX-sv.crt -text -nameopt multiline -sha1

if [ "$P12." = YES. ] ; then

   echo "$OPENSSL pkcs12 -export -des3 -out $PREFIX-sv.p12 -caname $CAPREFIX -name $PREFIX -inkey $PREFIX-sv.key -in $PREFIX-sv.crt -certfile $CAPREFIX-ca.crt "

   $OPENSSL pkcs12 -export -des3 -out $PREFIX-sv.p12 -caname $CAPREFIX -name $PREFIX -inkey $PREFIX-sv.key -in $PREFIX-sv.crt -certfile $CAPREFIX-ca.crt 

   read
fi

echo "openssl x509 -noout -text -hash -in $PREFIX-sv.selfcert -nameopt multiline"
$OPENSSL x509 -noout -text -hash -in $PREFIX-sv.crt -nameopt multiline

echo "openssl x509 -in $PREFIX-sv.crt -outform der -out $PREFIX-sv.der "
$OPENSSL x509 -in $PREFIX-sv.crt -outform der -out $PREFIX-sv.der 
read

# all together now
touch $PREFIX-sv.dhp
cat $PREFIX-sv.prm $PREFIX-sv.key  $PREFIX-sv.crt $PREFIX-sv.dhp >$PREFIX-sv.pem
chmod o-r $PREFIX-sv.prm  

echo "$PREFIX-sv.pem done"

 
