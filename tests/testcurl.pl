#!/usr/bin/env perl
#***************************************************************************
#                                  _   _ ____  _
#  Project                     ___| | | |  _ \| |
#                             / __| | | | |_) | |
#                            | (__| |_| |  _ <| |___
#                             \___|\___/|_| \_\_____|
#
# Copyright (C) 1998 - 2005, Daniel Stenberg, <daniel@haxx.se>, et al.
#
# This software is licensed as described in the file COPYING, which
# you should have received as part of this distribution. The terms
# are also available at http://curl.haxx.se/docs/copyright.html.
#
# You may opt to use, copy, modify, merge, publish, distribute and/or sell
# copies of the Software, and permit persons to whom the Software is
# furnished to do so, under the terms of the COPYING file.
#
# This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
# KIND, either express or implied.
#
# $Id$
###########################################################################

###########################
#  What is This Script?
###########################

# testcurl.pl is the master script to use for automatic testing of CVS-curl.
# This is written for the purpose of being run from a crontab job or similar
# at a regular interval. The output is suitable to be mailed to
# curl-autocompile@haxx.se to be dealt with automatically (make sure the
# subject includes the word "autobuild" as the mail gets silently discarded
# otherwise).  The most current build status (with a resonable backlog) will
# be published on the curl site, at http://curl.haxx.se/auto/

# USAGE:
# testcurl.pl [options] [curl-daily-name] > output

# Options:
#
# --configure=[options]    Configure options
# --crosscompile           This is a crosscompile
# --desc=[desc]            Description of your test system
# --email=[email]          Set email address to report as
# --mktarball=[command]    Command to run after completed test
# --name=[name]            Set name to report as
# --nocvsup                Don't update from CVS even though it is a CVS tree
# --runtestopts=[options]  Options to pass to runtests.pl
# --setup=[file name]      File name to read setup from (deprecated)
# --target=[your os]       Specify your target environment.
#
# if [curl-daily-name] is omitted, a 'curl' CVS directory is assumed.
#

use strict;

use Cwd;

# Turn on warnings (equivalent to -w, which can't be used with /usr/bin/env)
#BEGIN { $^W = 1; }

use vars qw($version $fixed $infixed $CURLDIR $CVS $pwd $build $buildlog
            $buildlogname $configurebuild $targetos $confsuffix $binext
            $libext);
use vars qw($name $email $desc $confopts $runtestopts $setupfile $mktarball
            $nocvsup $crosscompile);

# version of this script
$version='$Revision$';
$fixed=0;

# Determine if we're running from CVS or a canned copy of curl,
# or if we got a specific target option or setup file option.
$CURLDIR="curl";
$CVS=1;
$setupfile = 'setup';
while ($ARGV[0]) {
  if ($ARGV[0] =~ /--target=/) {
    $targetos = (split(/=/, shift @ARGV))[1];
  }
  elsif ($ARGV[0] =~ /--setup=/) {
    $setupfile = (split(/=/, shift @ARGV))[1];
  }
  elsif ($ARGV[0] =~ /--mktarball=/) {
    $mktarball = (split(/=/, shift @ARGV))[1];
  }
  elsif ($ARGV[0] =~ /--name=/) {
    $name = (split(/=/, shift @ARGV))[1];
  }
  elsif ($ARGV[0] =~ /--email=/) {
    $email = (split(/=/, shift @ARGV))[1];
  }
  elsif ($ARGV[0] =~ /--desc=/) {
    $desc = (split(/=/, shift @ARGV))[1];
  }
  elsif ($ARGV[0] =~ /--configure=/) {
    $confopts = (split(/=/, shift @ARGV))[1];
  }
  elsif ($ARGV[0] =~ /--nocvsup/) {
    $nocvsup=1;
    shift @ARGV;
  }
  elsif ($ARGV[0] =~ /--crosscompile/) {
    $crosscompile=1;
    shift @ARGV;
  }
  elsif ($ARGV[0] =~ /--runtestopts=/) {
    $runtestopts = (split(/=/, shift @ARGV, 2))[1];
  }
  else {
    $CURLDIR=shift @ARGV;
    $CVS=0;
  }
}

# Do the platform-specific stuff here
$configurebuild = 1;
$confsuffix = '';
$binext = '';
$libext = '.la'; # .la since both libcurl and libcares are made with libtool
if ($^O eq 'MSWin32' || $targetos) {
  if (!$targetos) {
    # If no target defined on Win32 lets assume vc
    $targetos = 'vc';
  }
  if ($targetos =~ /vc/ || $targetos =~ /mingw32/ || $targetos =~ /borland/) {
    $binext = '.exe';
    $libext = '.lib' if ($targetos =~ /vc/ || $targetos =~ /borland/);
    $libext = '.a' if ($targetos =~ /mingw32/);
  }
  elsif ($targetos =~ /netware/) {
    $configurebuild = 0;
    $binext = '.nlm';
    $libext = '.lib';
  }
}

if ($^O eq 'MSWin32') {

  # Set these things only when building ON Windows, not when simply building
  # FOR Windows since we might be cross-compiling on another system. Non-
  # Windows builds still default to configure-style builds with no confsuffix.

  $configurebuild = 0;
  $confsuffix = '-win32';
}


$ENV{LANG}="C";

sub rmtree($) {
    my $target = $_[0];
    if ($^O eq 'MSWin32') {
      foreach (glob($target)) {
        s:/:\\:g;
        system("rd /s /q $_");
      }
    } else {
      system("rm -rf $target");
    }
}

sub grepfile($$) {
    my ($target, $fn) = @_;
    open(F, $fn) or die;
    while (<F>) {
      if (/$target/) {
        close(F);
        return 1;
      }
    }
    close(F);
    return 0;
}

sub logit($) {
    my $text=$_[0];
    if ($text) {
      print "testcurl: $text\n";
    }
}

sub mydie($){
    my $text=$_[0];
    logit "$text";
    chdir $pwd; # cd back to the original root dir

    if ($pwd && $build) {
      # we have a build directory name, remove the dir
      logit "removing the $build dir";
      rmtree "$pwd/$build";
    }
    if (-r $buildlog) {
      # we have a build log output file left, remove it
      logit "removing the $buildlogname file";
      unlink "$buildlog";
    }
    logit "ENDING HERE"; # last line logged!
    exit 1;
}

if (open(F, "$setupfile")) {
  while (<F>) {
    if (/(\w+)=(.*)/) {
      eval "\$$1=$2;";
    }
  }
  close(F);
  $infixed=$fixed;
} else {
  $infixed=0;    # so that "additional args to configure" works properly first time...
}

if (!$name) {
  print "please enter your name\n";
  $name = <>;
  chomp $name;
  $fixed=1;
}

if (!$email) {
  print "please enter your contact email address\n";
  $email = <>;
  chomp $email;
  $fixed=2;
}

if (!$desc) {
  print "please enter a one line system description\n";
  $desc = <>;
  chomp $desc;
  $fixed=3;
}

if (!$confopts) {
  if ($infixed < 4) {
    print "please enter your additional arguments to configure\n";
    print "examples: --with-ssl --enable-debug --enable-ipv6 --with-krb4\n";
    $confopts = <>;
    chomp $confopts;
  }
}


if ($fixed < 4) {
    $fixed=4;
    open(F, ">$setupfile") or die;
    print F "name='$name'\n";
    print F "email='$email'\n";
    print F "desc='$desc'\n";
    print F "confopts='$confopts'\n";
    print F "fixed='$fixed'\n";
    close(F);
}

logit "STARTING HERE"; # first line logged, for scripts to trigger on
logit "NAME = $name";
logit "EMAIL = $email";
logit "DESC = $desc";
logit "CONFOPTS = $confopts";
logit "CFLAGS = ".$ENV{CFLAGS};
logit "LDFLAGS = ".$ENV{LDFLAGS};
logit "CC = ".$ENV{CC};
logit "target = ".$targetos;
logit "version = $version"; # script version
logit "date = ".(scalar gmtime)." UTC";

# Make $pwd to become the path without newline. We'll use that in order to cut
# off that path from all possible logs and error messages etc.
$pwd = cwd();

if (-d $CURLDIR) {
  if ($CVS && -d "$CURLDIR/CVS") {
    logit "$CURLDIR is verified to be a fine source dir";
    # remove the generated sources to force them to be re-generated each
    # time we run this test
    unlink "$CURLDIR/src/hugehelp.c";
  } elsif (!$CVS && -f "$CURLDIR/tests/testcurl.pl") {
    logit "$CURLDIR is verified to be a fine daily source dir"
  } else {
    mydie "$CURLDIR is not a daily source dir or checked out from CVS!"
  }
}
$build="build-$$";
$buildlogname="buildlog-$$";
$buildlog="$pwd/$buildlogname";

# remove any previous left-overs
rmtree "build-*";
rmtree "buildlog-*";

# this is to remove old build logs that ended up in the wrong dir
foreach (glob("$CURLDIR/buildlog-*")) { unlink $_; }

# create a dir to build in
mkdir $build, 0777;

if (-d $build) {
  logit "build dir $build was created fine";
} else {
  mydie "failed to create dir $build";
}

# get in the curl source tree root
chdir $CURLDIR;

# Do the CVS thing, or not...
if ($CVS) {

  # this is a temporary fix to make things work again, remove later
  logit "remove ares/aclocal.m4";
  unlink "ares/aclocal.m4";

  logit "update from CVS";
  my $cvsstat;

  sub cvsup() {
    # update quietly to the latest CVS
    logit "run cvs up";
    if($nocvsup) {
        logit "Skipping CVS update (--nocvsup)";
        return 1;
    }
    else {
        system("cvs -Q up -dP 2>&1");
    }

    $cvsstat=$?;

    # return !RETURNVALUE so that errors return 0 while goodness
    # returns 1
    return !$cvsstat;
  }

  my $att=0;
  while (!cvsup()) {
    $att++;
    logit "failed CVS update attempt number $att.";
    if ($att > 10) {
      $cvsstat=111;
      last; # get out of the loop
    }
    sleep 5;
  }

  if ($cvsstat != 0) {
    mydie "failed to update from CVS ($cvsstat), exiting";
  }

  # remove possible left-overs from the past
  unlink "configure";
  unlink "autom4te.cache";

  if ($configurebuild) {
    # generate the build files
    logit "invoke buildconf, but filter off the silly aclocal warnings";
    open(F, "./buildconf 2>&1 |") or die;
    open(LOG, ">$buildlog") or die;
    while (<F>) {
      next if /warning: underquoted definition of/;
      print;
      print LOG;
    }
    close(F);
    close(LOG);

    if (grepfile("^buildconf: OK", $buildlog)) {
      logit "buildconf was successful";
    }
    else {
      mydie "buildconf was NOT successful";
    }

    if($confopts =~ /--enable-ares/) {
        logit "run buildconf for ares";
        chdir "ares";
        open(F, "./buildconf 2>&1 |") or die;
        open(LOG, ">$buildlog") or die;
        while (<F>) {
            next if /warning: underquoted definition of/;
            print;
            print LOG;
        }
        close(F);
        close(LOG);
        chdir "..";
    }

  }
  else {
    logit "buildconf was successful (dummy message)";
  }
}

if ($configurebuild) {
  if (-f "configure") {
    logit "configure created";
  } else {
    mydie "no configure created";
  }
} else {
  logit "configure created (dummy message)"; # dummy message to feign success
}

# change to build dir
chdir "$pwd/$build";

if ($configurebuild) {
  # run configure script
  print `../$CURLDIR/configure $confopts 2>&1`;

  if (-f "lib/Makefile") {
    logit "configure seems to have finished fine";
  } else {
    mydie "configure didn't work";
  }
} else {
  if (($^O eq 'MSWin32') && ($targetos !~ /netware/)) {
    system("xcopy /s /q ..\\$CURLDIR .");
    system("buildconf.bat");
  }
  elsif (($^O eq 'linux') || ($targetos =~ /netware/)) {
    system("cp -afr ../$CURLDIR/* ."); 
    system("cp -af ../$CURLDIR/Makefile.dist Makefile"); 
    system("make -i -C lib -f Makefile.$targetos prebuild");
    system("make -i -C src -f Makefile.$targetos prebuild");
  }
}

logit "display lib/config$confsuffix.h";
open(F, "lib/config$confsuffix.h") or die "lib/config$confsuffix.h: $!";
while (<F>) {
  print if /^ *#/;
}
close(F);

logit "display src/config$confsuffix.h";
open(F, "src/config$confsuffix.h") or die "src/config$confsuffix.h: $!";
while (<F>) {
  print if /^ *#/;
}
close(F);

if (grepfile("define USE_ARES", "lib/config$confsuffix.h")) {
  logit "setup to build ares";

  logit "build ares";
  chdir "ares";

  if ($targetos && !$configurebuild) {
      open(F, "make -f Makefile.$targetos 2>&1 |") or die;
  }
  else {
      open(F, "make 2>&1 |") or die;
  }
  while (<F>) {
    s/$pwd//g;
    print;
  }
  close(F);

  if (-f "libcares$libext") {
    logit "ares is now built successfully (libcares$libext)";
  } else {
    logit "ares build failed (libares$libext)";
  }

  # cd back to the curl build dir
  chdir "$pwd/$build";
}

logit "run make";
if ($configurebuild) {
  open(F, "make -i 2>&1 |") or die;
  while (<F>) {
    s/$pwd//g;
    print;
  }
  close(F);
}
else {
  if ($^O eq 'MSWin32') {
    if ($targetos =~ /vc/) {
      open(F, "nmake -i $targetos|") or die;
    }
    else {
      open(F, "make -i $targetos |") or die;
    }
  }
  else {
    open(F, "make -i $targetos 2>&1 |") or die;
  }
  while (<F>) {
    s/$pwd//g;
    print;
  }
  close(F);
}

if (-f "lib/libcurl$libext") {
  logit "lib/libcurl was created fine (libcurl$libext)";
}
else {
  logit "lib/libcurl was not created (libcurl$libext)";
}

if (-f "src/curl$binext") {
  logit "src/curl was created fine (curl$binext)";
}
else {
  mydie "src/curl was not created (curl$binext)";
}

if ($targetos =~ /netware/) {
  if (-f '../../curlver') {
    system('../../curlver');
  }
}
elsif(!$crosscompile) {
  logit "display curl$binext --version output";
  system("./src/curl$binext --version");
}

if ($configurebuild && !$crosscompile) {
  my $o;
  if($runtestopts) {
      $o = "TEST_F=\"$runtestopts\" ";
  }
  logit "run make ${o}test-full";
  open(F, "make ${o}test-full 2>&1 |") or die;
  open(LOG, ">$buildlog") or die;
  while (<F>) {
    s/$pwd//g;
    print;
    print LOG;
  }
  close(F);
  close(LOG);

  if (grepfile("^TEST", $buildlog)) {
    logit "tests were run";
  } else {
    mydie "test suite failure";
  }

  if (grepfile("^TESTFAIL:", $buildlog)) {
    logit "the tests were not successful";
  } else {
    logit "the tests were successful!";
  }
} else {
  # dummy message to feign success
  if($crosscompile) {
    logit "cross-compiling, can't run tests";
  }
  print "TESTDONE: 1 tests out of 0 (dummy message)\n";
}

# create a tarball if we got that option.
if (($mktarball ne '') && (-f $mktarball)) {
  system($mktarball);
}

# mydie to cleanup
mydie "ending nicely";
