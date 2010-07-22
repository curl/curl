#!/usr/bin/perl -w
# ***************************************************************************
# *                                  _   _ ____  _
# *  Project                     ___| | | |  _ \| |
# *                             / __| | | | |_) | |
# *                            | (__| |_| |  _ <| |___
# *                             \___|\___/|_| \_\_____|
# *
# * Copyright (C) 1998 - 2010, Daniel Stenberg, <daniel@haxx.se>, et al.
# *
# * This software is licensed as described in the file COPYING, which
# * you should have received as part of this distribution. The terms
# * are also available at http://curl.haxx.se/docs/copyright.html.
# *
# * You may opt to use, copy, modify, merge, publish, distribute and/or sell
# * copies of the Software, and permit persons to whom the Software is
# * furnished to do so, under the terms of the COPYING file.
# *
# * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
# * KIND, either express or implied.
# *
# ***************************************************************************
# This Perl script creates a fresh ca-bundle.crt file for use with libcurl.
# It downloads certdata.txt from Mozilla's source tree (see URL below),
# then parses certdata.txt and extracts CA Root Certificates into PEM format.
# These are then processed with the OpenSSL commandline tool to produce the
# final ca-bundle.crt file.
# The script is based on the parse-certs script written by Roland Krikava.
# This Perl script works on almost any platform since its only external
# dependency is the OpenSSL commandline tool for optional text listing.
# Hacked by Guenter Knauf.
#
use Getopt::Std;
use MIME::Base64;
use LWP::UserAgent;
use strict;
use vars qw($opt_b $opt_h $opt_i $opt_l $opt_n $opt_q $opt_t $opt_u $opt_v);

my $url = 'http://mxr.mozilla.org/seamonkey/source/security/nss/lib/ckfw/builtins/certdata.txt?raw=1';
# If the OpenSSL commandline is not in search path you can configure it here!
my $openssl = 'openssl';

my $version = '1.14';

getopts('bhilnqtuv');

if ($opt_i) {
  print ("=" x 78 . "\n");
  print "Script Version            : $version\n";
  print "Perl Version              : $]\n";
  print "Operating System Name     : $^O\n";
  print "Getopt::Std.pm Version    : ${Getopt::Std::VERSION}\n";
  print "MIME::Base64.pm Version   : ${MIME::Base64::VERSION}\n";
  print "LWP::UserAgent.pm Version : ${LWP::UserAgent::VERSION}\n";
  print "LWP.pm Version            : ${LWP::VERSION}\n";
  print ("=" x 78 . "\n");
}

$0 =~ s/\\/\//g;
$0 = substr($0, rindex($0, '/') + 1);
if ($opt_h) {
  printf("Usage:\t%s [-b] [-i] [-l] [-n] [-q] [-t] [-u] [-v] [<outputfile>]\n", $0);
  print "\t-b\tbackup an existing version of ca-bundle.crt\n";
  print "\t-i\tprint version info about used modules\n";
  print "\t-l\tprint license info about certdata.txt\n";
  print "\t-n\tno download of certdata.txt (to use existing)\n";
  print "\t-q\tbe really quiet (no progress output at all)\n";
  print "\t-t\tinclude plain text listing of certificates\n";
  print "\t-u\tunlink (remove) certdata.txt after processing\n";
  print "\t-v\tbe verbose and print out processed CAs\n";
  exit;
}

my $crt = $ARGV[0] || 'ca-bundle.crt';
my $txt = substr($url, rindex($url, '/') + 1);
$txt =~ s/\?.*//;

if (!$opt_n || !-e $txt) {
  print "Downloading '$txt' ...\n" if (!$opt_q);
  my $ua  = new LWP::UserAgent(agent => "$0/$version");
  my $req = new HTTP::Request('GET', $url);
  my $res = $ua->request($req);
  if ($res->is_success) {
    open(TXT,">$txt") or die "Couldn't open $txt: $!";
    print TXT $res->content . "\n";
    close(TXT) or die "Couldn't close $txt: $!";
  } else {
    die $res->status_line;
  }
}

if ($opt_b && -e $crt) {
  my $bk = 1;
  while (-e "$crt.~${bk}~") {
    $bk++;
  }
  rename $crt, "$crt.~${bk}~";
}

my $format = $opt_t ? "plain text and " : "";
my $currentdate = scalar gmtime() . " UTC";
open(CRT,">$crt") or die "Couldn't open $crt: $!";
print CRT <<EOT;
##
## $crt -- Bundle of CA Root Certificates
##
## Converted at: ${currentdate}
##
## This is a bundle of X.509 certificates of public Certificate Authorities
## (CA). These were automatically extracted from Mozilla's root certificates
## file (certdata.txt).  This file can be found in the mozilla source tree:
## '/mozilla/security/nss/lib/ckfw/builtins/certdata.txt'
##
## It contains the certificates in ${format}PEM format and therefore
## can be directly used with curl / libcurl / php_curl, or with
## an Apache+mod_ssl webserver for SSL client authentication.
## Just configure this file as the SSLCACertificateFile.
##

EOT

close(CRT) or die "Couldn't close $crt: $!";

print "Processing  '$txt' ...\n" if (!$opt_q);
my $caname;
my $certnum = 0;
open(TXT,"$txt") or die "Couldn't open $txt: $!";
while (<TXT>) {
  if (/\*\*\*\*\* BEGIN LICENSE BLOCK \*\*\*\*\*/) {
    open(CRT, ">>$crt") or die "Couldn't open $crt: $!";
    print CRT;
    print if ($opt_l);
    while (<TXT>) {
      print CRT;
      print if ($opt_l);
      last if (/\*\*\*\*\* END LICENSE BLOCK \*\*\*\*\*/);
    }
    close(CRT) or die "Couldn't close $crt: $!";
  }
  next if /^#|^\s*$/;
  chomp;
  if (/^CVS_ID\s+\"(.*)\"/) {
    open(CRT, ">>$crt") or die "Couldn't open $crt: $!";
    print CRT "# $1\n";
    close(CRT) or die "Couldn't close $crt: $!";
  }
  if (/^CKA_LABEL\s+[A-Z0-9]+\s+\"(.*)\"/) {
    $caname = $1;
  }
  if (/^CKA_VALUE MULTILINE_OCTAL/) {
    my $data;
    while (<TXT>) {
      last if (/^END/);
      chomp;
      my @octets = split(/\\/);
      shift @octets;
      for (@octets) {
        $data .= chr(oct);
      }
    }
    my $pem = "-----BEGIN CERTIFICATE-----\n"
            . MIME::Base64::encode($data)
            . "-----END CERTIFICATE-----\n";
    open(CRT, ">>$crt") or die "Couldn't open $crt: $!";
    print CRT "\n$caname\n";
    print CRT ("=" x length($caname) . "\n");
    if (!$opt_t) {
      print CRT $pem;
    }
    close(CRT) or die "Couldn't close $crt: $!";
    if ($opt_t) {
      open(TMP, "|$openssl x509 -md5 -fingerprint -text -inform PEM >> $crt") or die "Couldn't open openssl pipe: $!";
      print TMP $pem;
      close(TMP) or die "Couldn't close openssl pipe: $!";
    }
    print "Parsing: $caname\n" if ($opt_v);
    $certnum ++;
  }
}
close(TXT) or die "Couldn't close $txt: $!";
unlink $txt if ($opt_u);
print "Done ($certnum CA certs processed).\n" if (!$opt_q);

exit;


