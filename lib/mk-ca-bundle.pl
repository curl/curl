#!/usr/bin/perl
# ***************************************************************************
# *                                  _   _ ____  _
# *  Project                     ___| | | |  _ \| |
# *                             / __| | | | |_) | |
# *                            | (__| |_| |  _ <| |___
# *                             \___|\___/|_| \_\_____|
# *
# * Copyright (C) 1998 - 2008, Daniel Stenberg, <daniel@haxx.se>, et al.
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
# * $Id$
# ***************************************************************************
# This Perl script creates a fresh ca-bundle.crt file for use with libcurl. 
# It downloads certdata.txt from Mozilla's source tree (see URL below),
# then parses certdata.txt and extracts CA Root Certificates into PEM format.
# These are then processed with the OpenSSL commandline tool to produce the
# final ca-bundle.crt file.
# The script is based on the parse-certs script writtten by Roland Krikava.
# This Perl script works on almost any platform since its only external
# dependency is the OpenSSL commandline tool.
# Hacked by Guenter Knauf.
#
use Getopt::Std;
use MIME::Base64;
use LWP::UserAgent;

my $url = 'http://lxr.mozilla.org/seamonkey/source/security/nss/lib/ckfw/builtins/certdata.txt?raw=1';
# If the OpenSSL commandline is not in search path you can configure it here!
my $openssl = 'openssl';

getopts('hilnuv');

if ($opt_h) {
  $0 =~ s/\\/\//g;
  printf("Usage:\t%s [-i] [-l] [-n] [-u] [-v] [<outputfile>]\n", substr($0, rindex($0, '/') + 1));
  print "\t-i\tprint version info about used modules\n";
  print "\t-l\tprint license info about certdata.txt\n";
  print "\t-n\tno download of certdata.txt (to use existing)\n";
  print "\t-u\tunlink (remove) certdata.txt after processing\n";
  print "\t-v\tbe verbose and print out processed CAs\n";
  exit;
}

if ($opt_i) {
  print "Perl Version              : $]\n";
  print "Operating System Name     : $^O\n";
  printf("MIME::Base64.pm Version   : %s\n", $MIME::Base64::VERSION);
  printf("LWP::UserAgent.pm Version : %s\n", $LWP::UserAgent::VERSION);
  print ("=" x 78 . "\n");
}

my $crt = $ARGV[0] || 'ca-bundle.crt';
my $tmp = 'mytmpfile.txt';
my $txt = substr($url, rindex($url, '/') + 1);
$txt =~ s/\?.*//;
if (!$opt_n) {
  print "Downloading '$txt' ...\n" if ($opt_v);
  my $ua  = new LWP::UserAgent;
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

die "File '$txt' doesnt exist - dont use -n switch to download the file!\n" if (!-e $txt);

my $currentdate = scalar gmtime() . " UTC";
open(CRT,">$crt") or die "Couldn't open $crt: $!";
print CRT <<EOT;
##
## $crt -- Bundle of CA Root Certificates
##
## Converted at: $currentdate
##
## This is a bundle of X.509 certificates of public Certificate Authorities
## (CA). These were automatically extracted from Mozilla's root certificates
## file (certdata.txt).  This file can be found in the mozilla source tree:
## '/mozilla/security/nss/lib/ckfw/builtins/certdata.txt'
##
## It contains the certificates in both plain text and PEM format
## and therefore can be directly used with curl / libcurl, or with an
## Apache+mod_ssl webserver for SSL client authentication.
## Just configure this file as the SSLCACertificateFile.
##

EOT

close(CRT) or die "Couldn't close $crt: $!";

my $certnum;
open(TXT,"$txt") or die "Couldn't open $file: $!";
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
  next if /^#/;
  next if /^\s*$/;
  chomp;
  if (/^CVS_ID\s+\"(.*)\"/) {
    open(CRT, ">>$crt") or die "Couldn't open $crt: $!";
    print CRT "# $1\n";
    close(CRT) or die "Couldn't close $crt: $!";
  }
  if (/^CKA_LABEL\s+[A-Z0-9]+\s+\"(.*)\"/) {
    $val = $1;
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
    open(CRT, ">>$crt") or die "Couldn't open $crt: $!";
    print CRT "\n";
    print CRT "$val\n";
    print CRT ("=" x length($val) . "\n");
    close(CRT) or die "Couldn't close $crt: $!";
    open(TMP, ">$tmp") or die "Couldn't open $tmp: $!";
    print TMP "$val\n";
    print TMP "-----BEGIN CERTIFICATE-----\n";
    print TMP MIME::Base64::encode($data);
    print TMP "-----END CERTIFICATE-----\n";
    close(TMP) or die "Couldn't close $tmp: $!";
    system("$openssl x509 -md5 -fingerprint -text -in $tmp -inform PEM >> $crt");
    print "Parsing: $val\n" if ($opt_v);
    $certnum ++;
  }
}
close(TXT) or die "Couldn't close $txt: $!";
unlink $txt if ($opt_u);
unlink $tmp;
print "Done ($certnum CA certs processed).\n";

exit;


