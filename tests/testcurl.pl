#!/usr/bin/env perl
#***************************************************************************
#                                  _   _ ____  _
#  Project                     ___| | | |  _ \| |
#                             / __| | | | |_) | |
#                            | (__| |_| |  _ <| |___
#                             \___|\___/|_| \_\_____|
#
# Copyright (C) 1998 - 2020, Daniel Stenberg, <daniel@haxx.se>, et al.
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
###########################################################################

###########################
#  What is This Script?
###########################

# testcurl.pl is the master script to use for automatic testing of curl
# directly off its source repository.
# This is written for the purpose of being run from a crontab job or similar
# at a regular interval. The output is suitable to be mailed to
# curl-autocompile@haxx.se to be dealt with automatically (make sure the
# subject includes the word "autobuild" as the mail gets silently discarded
# otherwise).  The most current build status (with a reasonable backlog) will
# be published on the curl site, at https://curl.se/auto/

# USAGE:
# testcurl.pl [options] [curl-daily-name] > output

# Options:
#
# --configure=[options]    Configure options
# --crosscompile           This is a crosscompile
# --desc=[desc]            Description of your test system
# --email=[email]          Set email address to report as
# --extvercmd=[command]    Command to use for displaying version with cross compiles.
# --mktarball=[command]    Command to run after completed test
# --name=[name]            Set name to report as
# --notes=[notes]          More human-readable information about this configuration
# --nocvsup                Don't pull from git even though it is a git tree
# --nogitpull              Don't pull from git even though it is a git tree
# --nobuildconf            Don't run buildconf
# --noconfigure            Don't run configure
# --runtestopts=[options]  Options to pass to runtests.pl
# --setup=[file name]      File name to read setup from (deprecated)
# --target=[your os]       Specify your target environment.
#
# if [curl-daily-name] is omitted, a 'curl' git directory is assumed.
#

use strict;

use Cwd;
use File::Spec;

# Turn on warnings (equivalent to -w, which can't be used with /usr/bin/env)
#BEGIN { $^W = 1; }

use vars qw($version $fixed $infixed $CURLDIR $git $pwd $build $buildlog
            $buildlogname $configurebuild $targetos $confheader $binext
            $libext);

use vars qw($name $email $desc $confopts $runtestopts $setupfile $mktarball
            $extvercmd $nogitpull $nobuildconf $crosscompile
            $timestamp $notes);

# version of this script
$version='2014-11-25';
$fixed=0;

# Determine if we're running from git or a canned copy of curl,
# or if we got a specific target option or setup file option.
$CURLDIR="curl";
if (-f ".git/config") {
  $CURLDIR = "./";
}

$git=1;
$setupfile = 'setup';
$configurebuild = 1;
while ($ARGV[0]) {
  if ($ARGV[0] =~ /--target=/) {
    $targetos = (split(/=/, shift @ARGV, 2))[1];
  }
  elsif ($ARGV[0] =~ /--setup=/) {
    $setupfile = (split(/=/, shift @ARGV, 2))[1];
  }
  elsif ($ARGV[0] =~ /--extvercmd=/) {
    $extvercmd = (split(/=/, shift @ARGV, 2))[1];
  }
  elsif ($ARGV[0] =~ /--mktarball=/) {
    $mktarball = (split(/=/, shift @ARGV, 2))[1];
  }
  elsif ($ARGV[0] =~ /--name=/) {
    $name = (split(/=/, shift @ARGV, 2))[1];
  }
  elsif ($ARGV[0] =~ /--email=/) {
    $email = (split(/=/, shift @ARGV, 2))[1];
  }
  elsif ($ARGV[0] =~ /--desc=/) {
    $desc = (split(/=/, shift @ARGV, 2))[1];
  }
  elsif ($ARGV[0] =~ /--notes=/) {
    $notes = (split(/=/, shift @ARGV, 2))[1];
  }
  elsif ($ARGV[0] =~ /--configure=(.*)/) {
    $confopts = $1;
    shift @ARGV;
  }
  elsif (($ARGV[0] eq "--nocvsup") || ($ARGV[0] eq "--nogitpull")) {
    $nogitpull=1;
    shift @ARGV;
  }
  elsif ($ARGV[0] =~ /--nobuildconf/) {
    $nobuildconf=1;
    shift @ARGV;
  }
  elsif ($ARGV[0] =~ /--noconfigure/) {
    $configurebuild=0;
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
    $git=0; # a given dir, assume not using git
  }
}

# Do the platform-specific stuff here
$confheader = 'curl_config.h';
$binext = '';
$libext = '.la'; # .la since both libcurl and libcares are made with libtool
if ($^O eq 'MSWin32' || $targetos) {
  if (!$targetos) {
    # If no target defined on Win32 lets assume vc
    $targetos = 'vc';
  }
  if ($targetos =~ /vc/ || $targetos =~ /borland/ || $targetos =~ /watcom/) {
    $binext = '.exe';
    $libext = '.lib';
  }
  elsif ($targetos =~ /mingw/) {
    $binext = '.exe';
    if ($^O eq 'MSWin32') {
      $libext = '.a';
    }
  }
  elsif ($targetos =~ /netware/) {
    $configurebuild = 0;
    $binext = '.nlm';
    if ($^O eq 'MSWin32') {
      $libext = '.lib';
    }
    else {
      $libext = '.a';
    }
  }
}

if (($^O eq 'MSWin32' || $^O eq 'cygwin' || $^O eq 'msys') &&
    ($targetos =~ /vc/ || $targetos =~ /mingw32/ ||
     $targetos =~ /borland/ || $targetos =~ /watcom/)) {

  # Set these things only when building ON Windows and for Win32 platform.
  # FOR Windows since we might be cross-compiling on another system. Non-
  # Windows builds still default to configure-style builds with curl_config.h.

  $configurebuild = 0;
  $confheader = 'config-win32.h';
}

$ENV{LC_ALL}="C" if (($ENV{LC_ALL}) && ($ENV{LC_ALL} !~ /^C$/));
$ENV{LC_CTYPE}="C" if (($ENV{LC_CTYPE}) && ($ENV{LC_CTYPE} !~ /^C$/));
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

sub logit_spaced($) {
    my $text=$_[0];
    if ($text) {
      print "\ntestcurl: $text\n\n";
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

sub get_host_triplet {
  my $triplet;
  my $configfile = "$pwd/$build/lib/curl_config.h";

  if(-f $configfile && -s $configfile && open(LIBCONFIGH, "<$configfile")) {
    while(<LIBCONFIGH>) {
      if($_ =~ /^\#define\s+OS\s+"*([^"][^"]*)"*\s*/) {
        $triplet = $1;
        last;
      }
    }
    close(LIBCONFIGH);
  }
  return $triplet;
}

if($name && $email && $desc) {
  # having these fields set are enough to continue, skip reading the setup
  # file
  $infixed=4;
  $fixed=4;
}
elsif (open(F, "$setupfile")) {
  while (<F>) {
    if (/(\w+)=(.*)/) {
      eval "\$$1=$2;";
    }
  }
  close(F);
  $infixed=$fixed;
}
else {
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
    print F "notes='$notes'\n";
    print F "fixed='$fixed'\n";
    close(F);
}

# Enable picky compiler warnings unless explicitly disabled
if (($confopts !~ /--enable-debug/) &&
    ($confopts !~ /--enable-warnings/) &&
    ($confopts !~ /--disable-warnings/)) {
  $confopts .= " --enable-warnings";
}

my $str1066os = 'o' x 1066;

# Set timestamp to the UTC this script is running. Its value might
# be changed later in the script to the value present in curlver.h
$timestamp = scalar(gmtime)." UTC";

logit "STARTING HERE"; # first line logged, for scripts to trigger on
logit 'TRANSFER CONTROL ==== 1120 CHAR LINE' . $str1066os . 'LINE_END';
logit "NAME = $name";
logit "EMAIL = $email";
logit "DESC = $desc";
logit "NOTES = $notes";
logit "CONFOPTS = $confopts";
logit "RUNTESTOPTS = ".$runtestopts;
logit "CPPFLAGS = ".$ENV{CPPFLAGS};
logit "CFLAGS = ".$ENV{CFLAGS};
logit "LDFLAGS = ".$ENV{LDFLAGS};
logit "LIBS = ".$ENV{LIBS};
logit "CC = ".$ENV{CC};
logit "TMPDIR = ".$ENV{TMPDIR};
logit "MAKEFLAGS = ".$ENV{MAKEFLAGS};
logit "ACLOCAL_FLAGS = ".$ENV{ACLOCAL_FLAGS};
logit "PKG_CONFIG_PATH = ".$ENV{PKG_CONFIG_PATH};
logit "DYLD_LIBRARY_PATH = ".$ENV{DYLD_LIBRARY_PATH};
logit "LD_LIBRARY_PATH = ".$ENV{LD_LIBRARY_PATH};
logit "LIBRARY_PATH = ".$ENV{LIBRARY_PATH};
logit "SHLIB_PATH = ".$ENV{SHLIB_PATH};
logit "LIBPATH = ".$ENV{LIBPATH};
logit "target = ".$targetos;
logit "version = $version"; # script version
logit "date = $timestamp";  # When the test build starts

$str1066os = undef;

# Make $pwd to become the path without newline. We'll use that in order to cut
# off that path from all possible logs and error messages etc.
$pwd = getcwd();

my $have_embedded_ares = 0;

if (-d $CURLDIR) {
  if ($git && -d "$CURLDIR/.git") {
    logit "$CURLDIR is verified to be a fine git source dir";
    # remove the generated sources to force them to be re-generated each
    # time we run this test
    unlink "$CURLDIR/src/tool_hugehelp.c";
    # find out if curl source dir has an in-tree c-ares repo
    $have_embedded_ares = 1 if (-f "$CURLDIR/ares/GIT-INFO");
  } elsif (!$git && -f "$CURLDIR/tests/testcurl.pl") {
    logit "$CURLDIR is verified to be a fine daily source dir";
    # find out if curl source dir has an in-tree c-ares extracted tarball
    $have_embedded_ares = 1 if (-f "$CURLDIR/ares/ares_build.h");
  } else {
    mydie "$CURLDIR is not a daily source dir or checked out from git!"
  }
}

# make the path absolute so we can use it everywhere
$CURLDIR = File::Spec->rel2abs("$CURLDIR");

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

# Do the git thing, or not...
if ($git) {
  my $gitstat = 0;
  my @commits;

  # update quietly to the latest git
  if($nogitpull) {
    logit "skipping git pull (--nogitpull)";
  } else {
    logit "run git pull in curl";
    system("git pull 2>&1");
    $gitstat += $?;
    logit "failed to update from curl git ($?), continue anyway" if ($?);

    # Set timestamp to the UTC the git update took place.
    $timestamp = scalar(gmtime)." UTC" if (!$gitstat);
  }

  # get the last 5 commits for show (even if no pull was made)
  @commits=`git log --pretty=oneline --abbrev-commit -5`;
  logit "The most recent curl git commits:";
  for (@commits) {
    chomp ($_);
    logit "  $_";
  }

  if (-d "ares/.git") {
    chdir "ares";

    if($nogitpull) {
      logit "skipping git pull (--nogitpull) in ares";
    } else {
      logit "run git pull in ares";
      system("git pull 2>&1");
      $gitstat += $?;
      logit "failed to update from ares git ($?), continue anyway" if ($?);

      # Set timestamp to the UTC the git update took place.
      $timestamp = scalar(gmtime)." UTC" if (!$gitstat);
    }

    # get the last 5 commits for show (even if no pull was made)
    @commits=`git log --pretty=oneline --abbrev-commit -5`;
    logit "The most recent ares git commits:";
    for (@commits) {
      chomp ($_);
      logit "  $_";
    }

    chdir "$CURLDIR";
  }

  if($nobuildconf) {
    logit "told to not run buildconf";
  }
  elsif ($configurebuild) {
    # remove possible left-overs from the past
    unlink "configure";
    unlink "autom4te.cache";

    # generate the build files
    logit "invoke buildconf";
    open(F, "./buildconf 2>&1 |") or die;
    open(LOG, ">$buildlog") or die;
    while (<F>) {
      my $ll = $_;
      print $ll;
      print LOG $ll;
    }
    close(F);
    close(LOG);

    logit "buildconf was successful";
  }
  else {
    logit "buildconf was successful (dummy message)";
  }
}

# Set timestamp to the one in curlver.h if this isn't a git test build.
if ((-f "include/curl/curlver.h") &&
    (open(F, "<include/curl/curlver.h"))) {
  while (<F>) {
    chomp;
    if ($_ =~ /^\#define\s+LIBCURL_TIMESTAMP\s+\"(.+)\".*$/) {
      my $stampstring = $1;
      if ($stampstring !~ /DEV/) {
          $stampstring =~ s/\s+UTC//;
          $timestamp = $stampstring." UTC";
      }
      last;
    }
  }
  close(F);
}

# Show timestamp we are using for this test build.
logit "timestamp = $timestamp";

if ($configurebuild) {
  if (-f "configure") {
    logit "configure created (at least it exists)";
  } else {
    mydie "no configure created/found";
  }
} else {
  logit "configure created (dummy message)"; # dummy message to feign success
}

sub findinpath {
  my $c;
  my $e;
  my $x = ($^O eq 'MSWin32') ? '.exe' : '';
  my $s = ($^O eq 'MSWin32') ? ';' : ':';
  my $p=$ENV{'PATH'};
  my @pa = split($s, $p);
  for $c (@_) {
    for $e (@pa) {
      if( -x "$e/$c$x") {
        return $c;
      }
    }
  }
}

my $make = findinpath("gmake", "make", "nmake");
if(!$make) {
    mydie "Couldn't find make in the PATH";
}
# force to 'nmake' for VC builds
$make = "nmake" if ($targetos =~ /vc/);
# force to 'wmake' for Watcom builds
$make = "wmake" if ($targetos =~ /watcom/);
logit "going with $make as make";

# change to build dir
chdir "$pwd/$build";

if ($configurebuild) {
  # run configure script
  print `$CURLDIR/configure $confopts 2>&1`;

  if (-f "lib/Makefile") {
    logit "configure seems to have finished fine";
  } else {
    mydie "configure didn't work";
  }
} else {
  logit "copying files to build dir ...";
  if (($^O eq 'MSWin32') && ($targetos !~ /netware/)) {
    system("xcopy /s /q \"$CURLDIR\" .");
    system("buildconf.bat");
  }
  elsif ($targetos =~ /netware/) {
    system("cp -afr $CURLDIR/* .");
    system("cp -af $CURLDIR/Makefile.dist Makefile");
    system("$make -i -C lib -f Makefile.netware prebuild");
    system("$make -i -C src -f Makefile.netware prebuild");
    if (-d "$CURLDIR/ares") {
      system("$make -i -C ares -f Makefile.netware prebuild");
    }
  }
  elsif ($^O eq 'linux') {
    system("cp -afr $CURLDIR/* .");
    system("cp -af $CURLDIR/Makefile.dist Makefile");
    system("$make -i -C lib -f Makefile.$targetos prebuild");
    system("$make -i -C src -f Makefile.$targetos prebuild");
    if (-d "$CURLDIR/ares") {
      system("cp -af $CURLDIR/ares/ares_build.h.dist ./ares/ares_build.h");
      system("$make -i -C ares -f Makefile.$targetos prebuild");
    }
  }
}

if(-f "./libcurl.pc") {
  logit_spaced "display libcurl.pc";
  if(open(F, "<./libcurl.pc")) {
    while(<F>) {
      my $ll = $_;
      print $ll if(($ll !~ /^ *#/) && ($ll !~ /^ *$/));
    }
    close(F);
  }
}

logit_spaced "display lib/$confheader";
open(F, "lib/$confheader") or die "lib/$confheader: $!";
while (<F>) {
  print if /^ *#/;
}
close(F);

if (($have_embedded_ares) &&
    (grepfile("^#define USE_ARES", "lib/$confheader"))) {
  print "\n";
  logit "setup to build ares";

  if(-f "./ares/libcares.pc") {
    logit_spaced  "display ares/libcares.pc";
    if(open(F, "<./ares/libcares.pc")) {
      while(<F>) {
        my $ll = $_;
        print $ll if(($ll !~ /^ *#/) && ($ll !~ /^ *$/));
      }
      close(F);
    }
  }

  if(-f "./ares/ares_build.h") {
    logit_spaced "display ares/ares_build.h";
    if(open(F, "<./ares/ares_build.h")) {
      while(<F>) {
        my $ll = $_;
        print $ll if(($ll =~ /^ *# *define *CARES_/) && ($ll !~ /__CARES_BUILD_H/));
      }
      close(F);
    }
  }
  else {
    mydie "no ares_build.h created/found";
  }

  $confheader =~ s/curl/ares/;
  logit_spaced "display ares/$confheader";
  if(open(F, "ares/$confheader")) {
      while (<F>) {
          print if /^ *#/;
      }
      close(F);
  }

  print "\n";
  logit "build ares";
  chdir "ares";

  if ($targetos && !$configurebuild) {
      logit "$make -f Makefile.$targetos";
      open(F, "$make -f Makefile.$targetos 2>&1 |") or die;
  }
  else {
      logit "$make";
      open(F, "$make 2>&1 |") or die;
  }
  while (<F>) {
    s/$pwd//g;
    print;
  }
  close(F);

  if (-f "libcares$libext") {
    logit "ares is now built successfully (libcares$libext)";
  } else {
    mydie "ares build failed (libcares$libext)";
  }

  # cd back to the curl build dir
  chdir "$pwd/$build";
}

my $mkcmd = "$make -i" . ($targetos && !$configurebuild ? " $targetos" : "");
logit "$mkcmd";
open(F, "$mkcmd 2>&1 |") or die;
while (<F>) {
  s/$pwd//g;
  print;
}
close(F);

if (-f "lib/libcurl$libext") {
  logit "libcurl was created fine (libcurl$libext)";
}
else {
  mydie "libcurl was not created (libcurl$libext)";
}

if (-f "src/curl$binext") {
  logit "curl was created fine (curl$binext)";
}
else {
  mydie "curl was not created (curl$binext)";
}

if (!$crosscompile || (($extvercmd ne '') && (-x $extvercmd))) {
  logit "display curl${binext} --version output";
  my $cmd = ($extvercmd ne '' ? $extvercmd.' ' : '')."./src/curl${binext} --version|";
  open(F, $cmd);
  while(<F>) {
    # strip CR from output on non-win32 platforms (wine on Linux)
    s/\r// if ($^O ne 'MSWin32');
    print;
  }
  close(F);
}

if ($configurebuild && !$crosscompile) {
  my $host_triplet = get_host_triplet();
  # build example programs for selected build targets
  if(($host_triplet =~ /([^-]+)-([^-]+)-irix(.*)/) ||
     ($host_triplet =~ /([^-]+)-([^-]+)-aix(.*)/) ||
     ($host_triplet =~ /([^-]+)-([^-]+)-osf(.*)/) ||
     ($host_triplet =~ /([^-]+)-([^-]+)-solaris2(.*)/)) {
    chdir "$pwd/$build/docs/examples";
    logit_spaced "build examples";
    open(F, "$make -i 2>&1 |") or die;
    open(LOG, ">$buildlog") or die;
    while (<F>) {
      s/$pwd//g;
      print;
      print LOG;
    }
    close(F);
    close(LOG);
    chdir "$pwd/$build";
  }
  # build and run full test suite
  my $o;
  if($runtestopts) {
      $o = "TEST_F=\"$runtestopts\" ";
  }
  logit "$make -k ${o}test-full";
  open(F, "$make -k ${o}test-full 2>&1 |") or die;
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
}
else {
  if($crosscompile) {
    my $host_triplet = get_host_triplet();
    # build example programs for selected cross-compiles
    if(($host_triplet =~ /([^-]+)-([^-]+)-mingw(.*)/) ||
       ($host_triplet =~ /([^-]+)-([^-]+)-android(.*)/)) {
      chdir "$pwd/$build/docs/examples";
      logit_spaced "build examples";
      open(F, "$make -i 2>&1 |") or die;
      open(LOG, ">$buildlog") or die;
      while (<F>) {
        s/$pwd//g;
        print;
        print LOG;
      }
      close(F);
      close(LOG);
      chdir "$pwd/$build";
    }
    # build test harness programs for selected cross-compiles
    if($host_triplet =~ /([^-]+)-([^-]+)-mingw(.*)/) {
      chdir "$pwd/$build/tests";
      logit_spaced "build test harness";
      open(F, "$make -i 2>&1 |") or die;
      open(LOG, ">$buildlog") or die;
      while (<F>) {
        s/$pwd//g;
        print;
        print LOG;
      }
      close(F);
      close(LOG);
      chdir "$pwd/$build";
    }
    logit_spaced "cross-compiling, can't run tests";
  }
  # dummy message to feign success
  print "TESTDONE: 1 tests out of 0 (dummy message)\n";
}

# create a tarball if we got that option.
if (($mktarball ne '') && (-x $mktarball)) {
  system($mktarball);
}

# mydie to cleanup
mydie "ending nicely";
