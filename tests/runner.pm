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

# This module contains entry points to run a single test. runner_init
# determines whether they will run in a separate process or in the process of
# the caller. The relevant interface is asynchronous so it will work in either
# case. Program arguments are marshalled and then written to the end of a pipe
# (in controlleripccall) which is later read from and the arguments
# unmarshalled (in ipcrecv) before the desired function is called normally.
# The function return values are then marshalled and written into another pipe
# (again in ipcrecv) when is later read from and unmarshalled (in runnerar)
# before being returned to the caller.

package runner;

use strict;
use warnings;
use 5.006;

BEGIN {
    use base qw(Exporter);

    our @EXPORT = qw(
        checktestcmd
        prepro
        readtestkeywords
        restore_test_env
        runner_init
        runnerac_clearlocks
        runnerac_shutdown
        runnerac_stopservers
        runnerac_test_preprocess
        runnerac_test_run
        runnerar
        runnerar_ready
        stderrfilename
        stdoutfilename
        $DBGCURL
        $gdb
        $gdbthis
        $gdbxwin
        $shallow
        $tortalloc
        $valgrind_logfile
        $valgrind_tool
    );

    # these are for debugging only
    our @EXPORT_OK = qw(
        singletest_preprocess
    );
}

use B qw(
    svref_2object
    );
use Storable qw(
    freeze
    thaw
    );

use pathhelp qw(
    exe_ext
    );
use processhelp qw(
    portable_sleep
    );
use servers qw(
    checkcmd
    clearlocks
    initserverconfig
    serverfortest
    stopserver
    stopservers
    subvariables
    );
use getpart;
use globalconfig;
use testutil qw(
    clearlogs
    logmsg
    runclient
    shell_quote
    subbase64
    subsha256base64file
    substrippemfile
    subnewlines
    );
use valgrind;


#######################################################################
# Global variables set elsewhere but used only by this package
# These may only be set *before* runner_init is called
our $DBGCURL=$CURL; #"../src/.libs/curl";  # alternative for debugging
our $valgrind_logfile="--log-file";  # the option name for valgrind >=3
our $valgrind_tool="--tool=memcheck";
our $gdb = checktestcmd("gdb");
our $gdbthis = 0;  # run test case with debugger (gdb or lldb)
our $gdbxwin;      # use windowed gdb when using gdb

# torture test variables
our $shallow;
our $tortalloc;

# local variables
my %oldenv;       # environment variables before test is started
my $UNITDIR="./unit";
my $CURLLOG="$LOGDIR/commands.log"; # all command lines run
my $defserverlogslocktimeout = 5; # timeout to await server logs lock removal
my $defpostcommanddelay = 0; # delay between command and postcheck sections
my $multiprocess;   # nonzero with a separate test runner process

# pipes
my $runnerr;        # pipe that runner reads from
my $runnerw;        # pipe that runner writes to

# per-runner variables, indexed by runner ID; these are used by controller only
my %controllerr;    # pipe that controller reads from
my %controllerw;    # pipe that controller writes to

# redirected stdout/stderr to these files
sub stdoutfilename {
    my ($logdir, $testnum)=@_;
    return "$logdir/stdout$testnum";
}

sub stderrfilename {
    my ($logdir, $testnum)=@_;
    return "$logdir/stderr$testnum";
}

#######################################################################
# Initialize the runner and prepare it to run tests
# The runner ID returned by this function must be passed into the other
# runnerac_* functions
# Called by controller
sub runner_init {
    my ($logdir, $jobs)=@_;

    $multiprocess = !!$jobs;

    # enable memory debugging if curl is compiled with it
    $ENV{'CURL_MEMDEBUG'} = "$logdir/$MEMDUMP";
    $ENV{'CURL_ENTROPY'}="12345678";
    $ENV{'CURL_FORCETIME'}=1; # for debug NTLM magic
    $ENV{'CURL_GLOBAL_INIT'}=1; # debug curl_global_init/cleanup use
    $ENV{'HOME'}=$pwd;
    $ENV{'CURL_HOME'}=$ENV{'HOME'};
    $ENV{'XDG_CONFIG_HOME'}=$ENV{'HOME'};
    $ENV{'COLUMNS'}=79; # screen width!

    # Incorporate the $logdir into the random seed and re-seed the PRNG.
    # This gives each runner a unique yet consistent seed which provides
    # more unique port number selection in each runner, yet is deterministic
    # across runs.
    $randseed += unpack('%16C*', $logdir);
    srand $randseed;

    # create pipes for communication with runner
    my ($thisrunnerr, $thiscontrollerw, $thiscontrollerr, $thisrunnerw);
    pipe $thisrunnerr, $thiscontrollerw;
    pipe $thiscontrollerr, $thisrunnerw;

    my $thisrunnerid;
    if($multiprocess) {
        # Create a separate process in multiprocess mode
        my $child = fork();
        if(0 == $child) {
            # TODO: set up better signal handlers
            $SIG{INT} = 'IGNORE';
            $SIG{TERM} = 'IGNORE';
            eval {
                # some msys2 perl versions don't define SIGUSR1
                $SIG{USR1} = 'IGNORE';
            };

            $thisrunnerid = $$;
            print "Runner $thisrunnerid starting\n" if($verbose);

            # Here we are the child (runner).
            close($thiscontrollerw);
            close($thiscontrollerr);
            $runnerr = $thisrunnerr;
            $runnerw = $thisrunnerw;

            # Set this directory as ours
            $LOGDIR = $logdir;
            mkdir("$LOGDIR/$PIDDIR", 0777);
            mkdir("$LOGDIR/$LOCKDIR", 0777);

            # Initialize various server variables
            initserverconfig();

            # handle IPC calls
            event_loop();

            # Can't rely on logmsg here in case it's buffered
            print "Runner $thisrunnerid exiting\n" if($verbose);

            # To reach this point, either the controller has sent
            # runnerac_stopservers() and runnerac_shutdown() or we have called
            # runnerabort(). In both cases, there are no more of our servers
            # running and we can safely exit.
            exit 0;
        }

        # Here we are the parent (controller).
        close($thisrunnerw);
        close($thisrunnerr);

        $thisrunnerid = $child;

    } else {
        # Create our pid directory
        mkdir("$LOGDIR/$PIDDIR", 0777);

        # Don't create a separate process
        $thisrunnerid = "integrated";
    }

    $controllerw{$thisrunnerid} = $thiscontrollerw;
    $runnerr = $thisrunnerr;
    $runnerw = $thisrunnerw;
    $controllerr{$thisrunnerid} = $thiscontrollerr;

    return $thisrunnerid;
}

#######################################################################
# Loop to execute incoming IPC calls until the shutdown call
sub event_loop {
    while () {
        if(ipcrecv()) {
            last;
        }
    }
}

#######################################################################
# Check for a command in the PATH of the machine running curl.
#
sub checktestcmd {
    my ($cmd)=@_;
    my @testpaths=("$LIBDIR/.libs", "$LIBDIR");
    return checkcmd($cmd, @testpaths);
}

# See if Valgrind should actually be used
sub use_valgrind {
    if($valgrind) {
        my @valgrindoption = getpart("verify", "valgrind");
        if((!@valgrindoption) || ($valgrindoption[0] !~ /disable/)) {
            return 1;
        }
    }
    return 0;
}

# Massage the command result code into a useful form
sub normalize_cmdres {
    my $cmdres = $_[0];
    my $signal_num  = $cmdres & 127;
    my $dumped_core = $cmdres & 128;

    if(!$anyway && ($signal_num || $dumped_core)) {
        $cmdres = 1000;
    }
    else {
        $cmdres >>= 8;
        $cmdres = (2000 + $signal_num) if($signal_num && !$cmdres);
    }
    return ($cmdres, $dumped_core);
}

# 'prepro' processes the input array and replaces %-variables in the array
# etc. Returns the processed version of the array
sub prepro {
    my $testnum = shift;
    my (@entiretest) = @_;
    my $show = 1;
    my @out;
    my $data_crlf;
    my @pshow;
    my @altshow;
    my $plvl;
    my $line;
    for my $s (@entiretest) {
        my $f = $s;
        $line++;
        if($s =~ /^ *%if ([A-Za-z0-9!_-]*)/) {
            my $cond = $1;
            my $rev = 0;

            if($cond =~ /^!(.*)/) {
                $cond = $1;
                $rev = 1;
            }
            $rev ^= $feature{$cond} ? 1 : 0;
            push @pshow, $show; # push the previous state
            $plvl++;
            if($show) {
                # only if this was showing before we can allow the alternative
                # to go showing as well
                push @altshow, $rev ^ 1; # push the reversed show state
            }
            else {
                push @altshow, 0; # the alt should still hide
            }
            if($show) {
                # we only allow show if already showing
                $show = $rev;
            }
            next;
        }
        elsif($s =~ /^ *%else/) {
            if(!$plvl) {
                print STDERR "error: test$testnum:$line: %else no %if\n";
                last;
            }
            $show = pop @altshow;
            push @altshow, $show; # put it back for consistency
            next;
        }
        elsif($s =~ /^ *%endif/) {
            if(!$plvl--) {
                print STDERR "error: test$testnum:$line: %endif had no %if\n";
                last;
            }
            $show = pop @pshow;
            pop @altshow; # not used here but we must pop it
            next;
        }
        if($show) {
            # The processor does CRLF replacements in the <data*> sections if
            # necessary since those parts might be read by separate servers.
            if($s =~ /^ *<data(.*)\>/) {
                if($1 =~ /crlf="yes"/ ||
                   ($feature{"hyper"} && ($keywords{"HTTP"} || $keywords{"HTTPS"}))) {
                    $data_crlf = 1;
                }
            }
            elsif(($s =~ /^ *<\/data/) && $data_crlf) {
                $data_crlf = 0;
            }
            subvariables(\$s, $testnum, "%");
            subbase64(\$s);
            subsha256base64file(\$s);
            substrippemfile(\$s);
            subnewlines(0, \$s) if($data_crlf);
            push @out, $s;
        }
    }
    return @out;
}


#######################################################################
# Load test keywords into %keywords hash
#
sub readtestkeywords {
    my @info_keywords = getpart("info", "keywords");

    # Clear the list of keywords from the last test
    %keywords = ();
    for my $k (@info_keywords) {
        chomp $k;
        $keywords{$k} = 1;
    }
}


#######################################################################
# Return a list of log locks that still exist
#
sub logslocked {
    opendir(my $lockdir, "$LOGDIR/$LOCKDIR");
    my @locks;
    foreach (readdir $lockdir) {
        if(/^(.*)\.lock$/) {
            push @locks, $1;
        }
    }
    return @locks;
}

#######################################################################
# Wait log locks to be unlocked
#
sub waitlockunlock {
    # If a server logs advisor read lock file exists, it is an indication
    # that the server has not yet finished writing out all its log files,
    # including server request log files used for protocol verification.
    # So, if the lock file exists the script waits here a certain amount
    # of time until the server removes it, or the given time expires.
    my $serverlogslocktimeout = shift;

    if($serverlogslocktimeout) {
        my $lockretry = $serverlogslocktimeout * 20;
        my @locks;
        while((@locks = logslocked()) && $lockretry--) {
            portable_sleep(0.05);
        }
        if(($lockretry < 0) &&
           ($serverlogslocktimeout >= $defserverlogslocktimeout)) {
            logmsg "Warning: server logs lock timeout ",
                   "($serverlogslocktimeout seconds) expired (locks: " .
                   join(", ", @locks) . ")\n";
        }
    }
}

#######################################################################
# Memory allocation test and failure torture testing.
#
sub torture {
    my ($testcmd, $testnum, $gdbline) = @_;

    # remove memdump first to be sure we get a new nice and clean one
    unlink("$LOGDIR/$MEMDUMP");

    # First get URL from test server, ignore the output/result
    runclient($testcmd);

    logmsg " CMD: $testcmd\n" if($verbose);

    # memanalyze -v is our friend, get the number of allocations made
    my $count=0;
    my @out = `$memanalyze -v "$LOGDIR/$MEMDUMP"`;
    for(@out) {
        if(/^Operations: (\d+)/) {
            $count = $1;
            last;
        }
    }
    if(!$count) {
        logmsg " found no functions to make fail\n";
        return 0;
    }

    my @ttests = (1 .. $count);
    if($shallow && ($shallow < $count)) {
        my $discard = scalar(@ttests) - $shallow;
        my $percent = sprintf("%.2f%%", $shallow * 100 / scalar(@ttests));
        logmsg " $count functions found, but only fail $shallow ($percent)\n";
        while($discard) {
            my $rm;
            do {
                # find a test to discard
                $rm = rand(scalar(@ttests));
            } while(!$ttests[$rm]);
            $ttests[$rm] = undef;
            $discard--;
        }
    }
    else {
        logmsg " $count functions to make fail\n";
    }

    for (@ttests) {
        my $limit = $_;
        my $fail;
        my $dumped_core;

        if(!defined($limit)) {
            # --shallow can undefine them
            next;
        }
        if($tortalloc && ($tortalloc != $limit)) {
            next;
        }

        if($verbose) {
            my ($sec,$min,$hour,$mday,$mon,$year,$wday,$yday,$isdst) =
                localtime(time());
            my $now = sprintf("%02d:%02d:%02d ", $hour, $min, $sec);
            logmsg "Fail function no: $limit at $now\r";
        }

        # make the memory allocation function number $limit return failure
        $ENV{'CURL_MEMLIMIT'} = $limit;

        # remove memdump first to be sure we get a new nice and clean one
        unlink("$LOGDIR/$MEMDUMP");

        my $cmd = $testcmd;
        if($valgrind && !$gdbthis) {
            my @valgrindoption = getpart("verify", "valgrind");
            if((!@valgrindoption) || ($valgrindoption[0] !~ /disable/)) {
                my $valgrindcmd = "$valgrind ";
                $valgrindcmd .= "$valgrind_tool " if($valgrind_tool);
                $valgrindcmd .= "--quiet --leak-check=yes ";
                $valgrindcmd .= "--suppressions=$srcdir/valgrind.supp ";
                # $valgrindcmd .= "--gen-suppressions=all ";
                $valgrindcmd .= "--num-callers=16 ";
                $valgrindcmd .= "${valgrind_logfile}=$LOGDIR/valgrind$testnum";
                $cmd = "$valgrindcmd $testcmd";
            }
        }
        logmsg "*** Function number $limit is now set to fail ***\n" if($gdbthis);

        my $ret = 0;
        if($gdbthis) {
            runclient($gdbline);
        }
        else {
            $ret = runclient($cmd);
        }
        #logmsg "$_ Returned " . ($ret >> 8) . "\n";

        # Now clear the variable again
        delete $ENV{'CURL_MEMLIMIT'} if($ENV{'CURL_MEMLIMIT'});

        if(-r "core") {
            # there's core file present now!
            logmsg " core dumped\n";
            $dumped_core = 1;
            $fail = 2;
        }

        if($valgrind) {
            my @e = valgrindparse("$LOGDIR/valgrind$testnum");
            if(@e && $e[0]) {
                if($automakestyle) {
                    logmsg "FAIL: torture $testnum - valgrind\n";
                }
                else {
                    logmsg " valgrind ERROR ";
                    logmsg @e;
                }
                $fail = 1;
            }
        }

        # verify that it returns a proper error code, doesn't leak memory
        # and doesn't core dump
        if(($ret & 255) || ($ret >> 8) >= 128) {
            logmsg " system() returned $ret\n";
            $fail=1;
        }
        else {
            my @memdata=`$memanalyze "$LOGDIR/$MEMDUMP"`;
            my $leak=0;
            for(@memdata) {
                if($_ ne "") {
                    # well it could be other memory problems as well, but
                    # we call it leak for short here
                    $leak=1;
                }
            }
            if($leak) {
                logmsg "** MEMORY FAILURE\n";
                logmsg @memdata;
                logmsg `$memanalyze -l "$LOGDIR/$MEMDUMP"`;
                $fail = 1;
            }
        }
        if($fail) {
            logmsg " $testnum: torture FAILED: function number $limit in test.\n",
            " invoke with \"-t$limit\" to repeat this single case.\n";
            stopservers($verbose);
            return 1;
        }
    }

    logmsg "\n" if($verbose);
    logmsg "torture OK\n";
    return 0;
}


#######################################################################
# restore environment variables that were modified in test
sub restore_test_env {
    my $deleteoldenv = $_[0];   # 1 to delete the saved contents after restore
    foreach my $var (keys %oldenv) {
        if($oldenv{$var} eq 'notset') {
            delete $ENV{$var} if($ENV{$var});
        }
        else {
            $ENV{$var} = $oldenv{$var};
        }
        if($deleteoldenv) {
            delete $oldenv{$var};
        }
    }
}


#######################################################################
# Start the servers needed to run this test case
sub singletest_startservers {
    my ($testnum, $testtimings) = @_;

    # remove old test server files before servers are started/verified
    unlink("$LOGDIR/$SERVERCMD");
    unlink("$LOGDIR/$SERVERIN");
    unlink("$LOGDIR/$PROXYIN");

    # timestamp required servers verification start
    $$testtimings{"timesrvrini"} = Time::HiRes::time();

    my $why;
    my $error;
    if (!$listonly) {
        my @what = getpart("client", "server");
        if(!$what[0]) {
            warn "Test case $testnum has no server(s) specified";
            $why = "no server specified";
            $error = -1;
        } else {
            my $err;
            ($why, $err) = serverfortest(@what);
            if($err == 1) {
                # Error indicates an actual problem starting the server
                $error = -2;
            } else {
                $error = -1;
            }
        }
    }

    # timestamp required servers verification end
    $$testtimings{"timesrvrend"} = Time::HiRes::time();

    return ($why, $error);
}


#######################################################################
# Generate preprocessed test file
sub singletest_preprocess {
    my $testnum = $_[0];

    # Save a preprocessed version of the entire test file. This allows more
    # "basic" test case readers to enjoy variable replacements.
    my @entiretest = fulltest();
    my $otest = "$LOGDIR/test$testnum";

    @entiretest = prepro($testnum, @entiretest);

    # save the new version
    open(my $fulltesth, ">", "$otest") || die "Failure writing test file";
    foreach my $bytes (@entiretest) {
        print $fulltesth pack('a*', $bytes) or die "Failed to print '$bytes': $!";
    }
    close($fulltesth) || die "Failure writing test file";

    # in case the process changed the file, reload it
    loadtest("$LOGDIR/test${testnum}");
}


#######################################################################
# Set up the test environment to run this test case
sub singletest_setenv {
    my @setenv = getpart("client", "setenv");
    foreach my $s (@setenv) {
        chomp $s;
        if($s =~ /([^=]*)(.*)/) {
            my ($var, $content) = ($1, $2);
            # remember current setting, to restore it once test runs
            $oldenv{$var} = ($ENV{$var})?"$ENV{$var}":'notset';

            if($content =~ /^=(.*)/) {
                # assign it
                $content = $1;

                if($var =~ /^LD_PRELOAD/) {
                    if(exe_ext('TOOL') && (exe_ext('TOOL') eq '.exe')) {
                        logmsg "Skipping LD_PRELOAD due to lack of OS support\n" if($verbose);
                        next;
                    }
                    if($feature{"Debug"} || !$has_shared) {
                        logmsg "Skipping LD_PRELOAD due to no release shared build\n" if($verbose);
                        next;
                    }
                }
                $ENV{$var} = "$content";
                logmsg "setenv $var = $content\n" if($verbose);
            }
            else {
                # remove it
                delete $ENV{$var} if($ENV{$var});
            }

        }
    }
    if($proxy_address) {
        $ENV{http_proxy} = $proxy_address;
        $ENV{HTTPS_PROXY} = $proxy_address;
    }
}


#######################################################################
# Check that test environment is fine to run this test case
sub singletest_precheck {
    my $testnum = $_[0];
    my $why;
    my @precheck = getpart("client", "precheck");
    if(@precheck) {
        my $cmd = $precheck[0];
        chomp $cmd;
        if($cmd) {
            my @p = split(/ /, $cmd);
            if($p[0] !~ /\//) {
                # the first word, the command, does not contain a slash so
                # we will scan the "improved" PATH to find the command to
                # be able to run it
                my $fullp = checktestcmd($p[0]);

                if($fullp) {
                    $p[0] = $fullp;
                }
                $cmd = join(" ", @p);
            }

            my @o = `$cmd 2> $LOGDIR/precheck-$testnum`;
            if($o[0]) {
                $why = $o[0];
                $why =~ s/[\r\n]//g;
            }
            elsif($?) {
                $why = "precheck command error";
            }
            logmsg "prechecked $cmd\n" if($verbose);
        }
    }
    return $why;
}


#######################################################################
# Prepare the test environment to run this test case
sub singletest_prepare {
    my ($testnum) = @_;

    if($feature{"TrackMemory"}) {
        unlink("$LOGDIR/$MEMDUMP");
    }
    unlink("core");

    # remove server output logfiles after servers are started/verified
    unlink("$LOGDIR/$SERVERIN");
    unlink("$LOGDIR/$PROXYIN");

    # if this section exists, it might be FTP server instructions:
    my @ftpservercmd = getpart("reply", "servercmd");
    push @ftpservercmd, "Testnum $testnum\n";
    # write the instructions to file
    writearray("$LOGDIR/$SERVERCMD", \@ftpservercmd);

    # create (possibly-empty) files before starting the test
    for my $partsuffix (('', '1', '2', '3', '4')) {
        my @inputfile=getpart("client", "file".$partsuffix);
        my %fileattr = getpartattr("client", "file".$partsuffix);
        my $filename=$fileattr{'name'};
        if(@inputfile || $filename) {
            if(!$filename) {
                logmsg " $testnum: IGNORED: section client=>file has no name attribute\n";
                return -1;
            }
            my $fileContent = join('', @inputfile);

            # make directories if needed
            my $path = $filename;
            # cut off the file name part
            $path =~ s/^(.*)\/[^\/]*/$1/;
            my @ldparts = split(/\//, $LOGDIR);
            my $nparts = @ldparts;
            my @parts = split(/\//, $path);
            if(join("/", @parts[0..$nparts-1]) eq $LOGDIR) {
                # the file is in $LOGDIR/
                my $d = shift @parts;
                for(@parts) {
                    $d .= "/$_";
                    mkdir $d; # 0777
                }
            }
            if (open(my $outfile, ">", "$filename")) {
                binmode $outfile; # for crapage systems, use binary
                if($fileattr{'nonewline'}) {
                    # cut off the final newline
                    chomp($fileContent);
                }
                print $outfile $fileContent;
                close($outfile);
            } else {
                logmsg "ERROR: cannot write $filename\n";
            }
        }
    }
    return 0;
}


#######################################################################
# Run the test command
sub singletest_run {
    my ($testnum, $testtimings) = @_;

    # get the command line options to use
    my ($cmd, @blaha)= getpart("client", "command");
    if($cmd) {
        # make some nice replace operations
        $cmd =~ s/\n//g; # no newlines please
        # substitute variables in the command line
    }
    else {
        # there was no command given, use something silly
        $cmd="-";
    }

    my $CURLOUT="$LOGDIR/curl$testnum.out"; # curl output if not stdout

    # if stdout section exists, we verify that the stdout contained this:
    my $out="";
    my %cmdhash = getpartattr("client", "command");
    if((!$cmdhash{'option'}) || ($cmdhash{'option'} !~ /no-output/)) {
        #We may slap on --output!
        if (!partexists("verify", "stdout") ||
                ($cmdhash{'option'} && $cmdhash{'option'} =~ /force-output/)) {
            $out=" --output $CURLOUT ";
        }
    }

    my @codepieces = getpart("client", "tool");
    my $tool="";
    if(@codepieces) {
        $tool = $codepieces[0];
        chomp $tool;
        $tool .= exe_ext('TOOL');
    }

    my $disablevalgrind;
    my $CMDLINE="";
    my $cmdargs;
    my $cmdtype = $cmdhash{'type'} || "default";
    my $fail_due_event_based = $run_event_based;
    if($cmdtype eq "perl") {
        # run the command line prepended with "perl"
        $cmdargs ="$cmd";
        $CMDLINE = "$perl ";
        $tool=$CMDLINE;
        $disablevalgrind=1;
    }
    elsif($cmdtype eq "shell") {
        # run the command line prepended with "/bin/sh"
        $cmdargs ="$cmd";
        $CMDLINE = "/bin/sh ";
        $tool=$CMDLINE;
        $disablevalgrind=1;
    }
    elsif(!$tool && !$keywords{"unittest"}) {
        # run curl, add suitable command line options
        my $inc="";
        if((!$cmdhash{'option'}) || ($cmdhash{'option'} !~ /no-include/)) {
            $inc = " --include";
        }
        $cmdargs = "$out$inc ";

        if($cmdhash{'option'} && ($cmdhash{'option'} =~ /binary-trace/)) {
            $cmdargs .= "--trace $LOGDIR/trace$testnum ";
        }
        else {
            $cmdargs .= "--trace-ascii $LOGDIR/trace$testnum ";
        }
        $cmdargs .= "--trace-config all ";
        $cmdargs .= "--trace-time ";
        if($run_event_based) {
            $cmdargs .= "--test-event ";
            $fail_due_event_based--;
        }
        $cmdargs .= $cmd;
        if ($proxy_address) {
            $cmdargs .= " --proxy $proxy_address ";
        }
    }
    else {
        $cmdargs = " $cmd"; # $cmd is the command line for the test file
        $CURLOUT = stdoutfilename($LOGDIR, $testnum); # sends received data to stdout

        # Default the tool to a unit test with the same name as the test spec
        if($keywords{"unittest"} && !$tool) {
            $tool="unit$testnum";
        }

        if($tool =~ /^lib/) {
            $CMDLINE="$LIBDIR/$tool";
        }
        elsif($tool =~ /^unit/) {
            $CMDLINE="$UNITDIR/$tool";
        }

        if(! -f $CMDLINE) {
            logmsg " $testnum: IGNORED: The tool set in the test case for this: '$tool' does not exist\n";
            return (-1, 0, 0, "", "", 0);
        }
        $DBGCURL=$CMDLINE;
    }

    if($fail_due_event_based) {
        logmsg " $testnum: IGNORED: This test cannot run event based\n";
        return (-1, 0, 0, "", "", 0);
    }

    if($gdbthis) {
        # gdb is incompatible with valgrind, so disable it when debugging
        # Perhaps a better approach would be to run it under valgrind anyway
        # with --db-attach=yes or --vgdb=yes.
        $disablevalgrind=1;
    }

    my @stdintest = getpart("client", "stdin");

    if(@stdintest) {
        my $stdinfile="$LOGDIR/stdin-for-$testnum";

        my %hash = getpartattr("client", "stdin");
        if($hash{'nonewline'}) {
            # cut off the final newline from the final line of the stdin data
            chomp($stdintest[-1]);
        }

        writearray($stdinfile, \@stdintest);

        $cmdargs .= " <$stdinfile";
    }

    if(!$tool) {
        $CMDLINE=shell_quote($CURL);
        if((!$cmdhash{'option'}) || ($cmdhash{'option'} !~ /no-q/)) {
            $CMDLINE .= " -q";
        }
    }

    if(use_valgrind() && !$disablevalgrind) {
        my $valgrindcmd = "$valgrind ";
        $valgrindcmd .= "$valgrind_tool " if($valgrind_tool);
        $valgrindcmd .= "--quiet --leak-check=yes ";
        $valgrindcmd .= "--suppressions=$srcdir/valgrind.supp ";
        # $valgrindcmd .= "--gen-suppressions=all ";
        $valgrindcmd .= "--num-callers=16 ";
        $valgrindcmd .= "${valgrind_logfile}=$LOGDIR/valgrind$testnum";
        $CMDLINE = "$valgrindcmd $CMDLINE";
    }

    $CMDLINE .= "$cmdargs > " . stdoutfilename($LOGDIR, $testnum) .
                " 2> " . stderrfilename($LOGDIR, $testnum);

    if($verbose) {
        logmsg "$CMDLINE\n";
    }

    open(my $cmdlog, ">", $CURLLOG) || die "Failure writing log file";
    print $cmdlog "$CMDLINE\n";
    close($cmdlog) || die "Failure writing log file";

    my $dumped_core;
    my $cmdres;

    if($gdbthis) {
        my $gdbinit = "$TESTDIR/gdbinit$testnum";
        open(my $gdbcmd, ">", "$LOGDIR/gdbcmd") || die "Failure writing gdb file";
        if($gdbthis == 1) {
            # gdb mode
            print $gdbcmd "set args $cmdargs\n";
            print $gdbcmd "show args\n";
            print $gdbcmd "source $gdbinit\n" if -e $gdbinit;
        }
        else {
            # lldb mode
            print $gdbcmd "set args $cmdargs\n";
        }
        close($gdbcmd) || die "Failure writing gdb file";
    }

    # Flush output.
    $| = 1;

    # timestamp starting of test command
    $$testtimings{"timetoolini"} = Time::HiRes::time();

    # run the command line we built
    if ($torture) {
        $cmdres = torture($CMDLINE,
                          $testnum,
                          "$gdb --directory $LIBDIR " . shell_quote($DBGCURL) . " -x $LOGDIR/gdbcmd");
    }
    elsif($gdbthis == 1) {
        # gdb
        my $GDBW = ($gdbxwin) ? "-w" : "";
        runclient("$gdb --directory $LIBDIR " . shell_quote($DBGCURL) . " $GDBW -x $LOGDIR/gdbcmd");
        $cmdres=0; # makes it always continue after a debugged run
    }
    elsif($gdbthis == 2) {
        # $gdb is "lldb"
        print "runs lldb -- $CURL $cmdargs\n";
        runclient("lldb -- $CURL $cmdargs");
        $cmdres=0; # makes it always continue after a debugged run
    }
    else {
        # Convert the raw result code into a more useful one
        ($cmdres, $dumped_core) = normalize_cmdres(runclient("$CMDLINE"));
    }

    # timestamp finishing of test command
    $$testtimings{"timetoolend"} = Time::HiRes::time();

    return (0, $cmdres, $dumped_core, $CURLOUT, $tool, use_valgrind() && !$disablevalgrind);
}


#######################################################################
# Clean up after test command
sub singletest_clean {
    my ($testnum, $dumped_core, $testtimings)=@_;

    if(!$dumped_core) {
        if(-r "core") {
            # there's core file present now!
            $dumped_core = 1;
        }
    }

    if($dumped_core) {
        logmsg "core dumped\n";
        if(0 && $gdb) {
            logmsg "running gdb for post-mortem analysis:\n";
            open(my $gdbcmd, ">", "$LOGDIR/gdbcmd2") || die "Failure writing gdb file";
            print $gdbcmd "bt\n";
            close($gdbcmd) || die "Failure writing gdb file";
            runclient("$gdb --directory libtest -x $LOGDIR/gdbcmd2 -batch " . shell_quote($DBGCURL) . " core ");
     #       unlink("$LOGDIR/gdbcmd2");
        }
    }

    my $serverlogslocktimeout = $defserverlogslocktimeout;
    my %cmdhash = getpartattr("client", "command");
    if($cmdhash{'timeout'}) {
        # test is allowed to override default server logs lock timeout
        if($cmdhash{'timeout'} =~ /(\d+)/) {
            $serverlogslocktimeout = $1 if($1 >= 0);
        }
    }

    # Test harness ssh server does not have this synchronization mechanism,
    # this implies that some ssh server based tests might need a small delay
    # once that the client command has run to avoid false test failures.
    #
    # gnutls-serv also lacks this synchronization mechanism, so gnutls-serv
    # based tests might need a small delay once that the client command has
    # run to avoid false test failures.
    my $postcommanddelay = $defpostcommanddelay;
    if($cmdhash{'delay'}) {
        # test is allowed to specify a delay after command is executed
        if($cmdhash{'delay'} =~ /(\d+)/) {
            $postcommanddelay = $1 if($1 > 0);
        }
    }

    portable_sleep($postcommanddelay) if($postcommanddelay);

    my @killtestservers = getpart("client", "killserver");
    if(@killtestservers) {
        foreach my $server (@killtestservers) {
            chomp $server;
            if(stopserver($server)) {
                logmsg " $testnum: killserver FAILED\n";
                return 1; # normal error if asked to fail on unexpected alive
            }
        }
    }

    # wait for any servers left running to release their locks
    waitlockunlock($serverlogslocktimeout);

    # timestamp removal of server logs advisor read lock
    $$testtimings{"timesrvrlog"} = Time::HiRes::time();

    # test definition might instruct to stop some servers
    # stop also all servers relative to the given one

    return 0;
}

#######################################################################
# Verify that the postcheck succeeded
sub singletest_postcheck {
    my ($testnum)=@_;

    # run the postcheck command
    my @postcheck= getpart("client", "postcheck");
    if(@postcheck) {
        my $cmd = join("", @postcheck);
        chomp $cmd;
        if($cmd) {
            logmsg "postcheck $cmd\n" if($verbose);
            my $rc = runclient("$cmd");
            # Must run the postcheck command in torture mode in order
            # to clean up, but the result can't be relied upon.
            if($rc != 0 && !$torture) {
                logmsg " $testnum: postcheck FAILED\n";
                return -1;
            }
        }
    }
    return 0;
}



###################################################################
# Get ready to run a single test case
sub runner_test_preprocess {
    my ($testnum)=@_;
    my %testtimings;

    if(clearlogs()) {
        logmsg "Warning: log messages were lost\n";
    }

    # timestamp test preparation start
    # TODO: this metric now shows only a portion of the prep time; better would
    # be to time singletest_preprocess below instead
    $testtimings{"timeprepini"} = Time::HiRes::time();

    ###################################################################
    # Load test metadata
    # ignore any error here--if there were one, it would have been
    # caught during the selection phase and this test would not be
    # running now
    loadtest("${TESTDIR}/test${testnum}");
    readtestkeywords();

    ###################################################################
    # Restore environment variables that were modified in a previous run.
    # Test definition may instruct to (un)set environment vars.
    restore_test_env(1);

    ###################################################################
    # Start the servers needed to run this test case
    my ($why, $error) = singletest_startservers($testnum, \%testtimings);

    # make sure no locks left for responsive test
    waitlockunlock($defserverlogslocktimeout);

    if(!$why) {

        ###############################################################
        # Generate preprocessed test file
        # This must be done after the servers are started so server
        # variables are available for substitution.
        singletest_preprocess($testnum);

        ###############################################################
        # Set up the test environment to run this test case
        singletest_setenv();

        ###############################################################
        # Check that the test environment is fine to run this test case
        if (!$listonly) {
            $why = singletest_precheck($testnum);
            $error = -1;
        }
    }
    return ($why, $error, clearlogs(), \%testtimings);
}


###################################################################
# Run a single test case with an environment that already been prepared
# Returns 0=success, -1=skippable failure, -2=permanent error,
#   1=unskippable test failure, as first integer, plus any log messages,
#   plus more return values when error is 0
sub runner_test_run {
    my ($testnum)=@_;

    if(clearlogs()) {
        logmsg "Warning: log messages were lost\n";
    }

    #######################################################################
    # Prepare the test environment to run this test case
    my $error = singletest_prepare($testnum);
    if($error) {
        return (-2, clearlogs());
    }

    #######################################################################
    # Run the test command
    my %testtimings;
    my $cmdres;
    my $dumped_core;
    my $CURLOUT;
    my $tool;
    my $usedvalgrind;
    ($error, $cmdres, $dumped_core, $CURLOUT, $tool, $usedvalgrind) = singletest_run($testnum, \%testtimings);
    if($error) {
        return (-2, clearlogs(), \%testtimings);
    }

    #######################################################################
    # Clean up after test command
    $error = singletest_clean($testnum, $dumped_core, \%testtimings);
    if($error) {
        return ($error, clearlogs(), \%testtimings);
    }

    #######################################################################
    # Verify that the postcheck succeeded
    $error = singletest_postcheck($testnum);
    if($error) {
        return ($error, clearlogs(), \%testtimings);
    }

    #######################################################################
    # restore environment variables that were modified
    restore_test_env(0);

    return (0, clearlogs(), \%testtimings, $cmdres, $CURLOUT, $tool, $usedvalgrind);
}

# Async call runner_clearlocks
# Called by controller
sub runnerac_clearlocks {
    return controlleripccall(\&runner_clearlocks, @_);
}

# Async call runner_shutdown
# This call does NOT generate an IPC response and must be the last IPC call
# received.
# Called by controller
sub runnerac_shutdown {
    my ($runnerid)=$_[0];
    my $err = controlleripccall(\&runner_shutdown, @_);

    # These have no more use
    close($controllerw{$runnerid});
    undef $controllerw{$runnerid};
    close($controllerr{$runnerid});
    undef $controllerr{$runnerid};
    return $err;
}

# Async call of runner_stopservers
# Called by controller
sub runnerac_stopservers {
    return controlleripccall(\&runner_stopservers, @_);
}

# Async call of runner_test_preprocess
# Called by controller
sub runnerac_test_preprocess {
    return controlleripccall(\&runner_test_preprocess, @_);
}

# Async call of runner_test_run
# Called by controller
sub runnerac_test_run {
    return controlleripccall(\&runner_test_run, @_);
}

###################################################################
# Call an arbitrary function via IPC
# The first argument is the function reference, the second is the runner ID
# Returns 0 on success, -1 on error writing to runner
# Called by controller (indirectly, via a more specific function)
sub controlleripccall {
    my $funcref = shift @_;
    my $runnerid = shift @_;
    # Get the name of the function from the reference
    my $cv = svref_2object($funcref);
    my $gv = $cv->GV;
    # Prepend the name to the function arguments so it's marshalled along with them
    unshift @_, $gv->NAME;
    # Marshall the arguments into a flat string
    my $margs = freeze \@_;

    # Send IPC call via pipe
    my $err;
    while(! defined ($err = syswrite($controllerw{$runnerid}, (pack "L", length($margs)) . $margs)) || $err <= 0) {
        if((!defined $err && ! $!{EINTR}) || (defined $err && $err == 0)) {
            # Runner has likely died
            return -1;
        }
        # system call was interrupted, probably by ^C; restart it so we stay in sync
    }

    if(!$multiprocess) {
        # Call the remote function here in single process mode
        ipcrecv();
     }
     return 0;
}

###################################################################
# Receive async response of a previous call via IPC
# The first return value is the runner ID or undef on error
# Called by controller
sub runnerar {
    my ($runnerid) = @_;
    my $err;
    my $datalen;
    while(! defined ($err = sysread($controllerr{$runnerid}, $datalen, 4)) || $err <= 0) {
        if((!defined $err && ! $!{EINTR}) || (defined $err && $err == 0)) {
            # Runner is likely dead and closed the pipe
            return undef;
        }
        # system call was interrupted, probably by ^C; restart it so we stay in sync
    }
    my $len=unpack("L", $datalen);
    my $buf;
    while(! defined ($err = sysread($controllerr{$runnerid}, $buf, $len)) || $err <= 0) {
        if((!defined $err && ! $!{EINTR}) || (defined $err && $err == 0)) {
            # Runner is likely dead and closed the pipe
            return undef;
        }
        # system call was interrupted, probably by ^C; restart it so we stay in sync
    }

    # Decode response values
    my $resarrayref = thaw $buf;

    # First argument is runner ID
    # TODO: remove this; it's unneeded since it's passed in
    unshift @$resarrayref, $runnerid;
    return @$resarrayref;
}

###################################################################
# Returns runner ID if a response from an async call is ready or error
# First value is ready, second is error, however an error case shows up
# as ready in Linux, so you can't trust it.
# argument is 0 for nonblocking, undef for blocking, anything else for timeout
# Called by controller
sub runnerar_ready {
    my ($blocking) = @_;
    my $rin = "";
    my %idbyfileno;
    my $maxfileno=0;
    foreach my $p (keys(%controllerr)) {
        my $fd = fileno($controllerr{$p});
        vec($rin, $fd, 1) = 1;
        $idbyfileno{$fd} = $p;  # save the runner ID for each pipe fd
        if($fd > $maxfileno) {
            $maxfileno = $fd;
        }
    }
    $maxfileno || die "Internal error: no runners are available to wait on\n";

    # Wait for any pipe from any runner to be ready
    # This may be interrupted and return EINTR, but this is ignored and the
    # caller will need to later call this function again.
    # TODO: this is relatively slow with hundreds of fds
    my $ein = $rin;
    if(select(my $rout=$rin, undef, my $eout=$ein, $blocking) >= 1) {
        for my $fd (0..$maxfileno) {
            # Return an error condition first in case it's both
            if(vec($eout, $fd, 1)) {
                return (undef, $idbyfileno{$fd});
            }
            if(vec($rout, $fd, 1)) {
                return ($idbyfileno{$fd}, undef);
            }
        }
        die "Internal pipe readiness inconsistency\n";
    }
    return (undef, undef);
}


###################################################################
# Cleanly abort and exit the runner
# This uses print since there is no longer any controller to write logs.
sub runnerabort{
    print "Controller is gone: runner $$ for $LOGDIR exiting\n";
    my ($error, $logs) = runner_stopservers();
    print $logs;
    runner_shutdown();
}

###################################################################
# Receive an IPC call in the runner and execute it
# The IPC is read from the $runnerr pipe and the response is
# written to the $runnerw pipe
# Returns 0 if more IPC calls are expected or 1 if the runner should exit
sub ipcrecv {
    my $err;
    my $datalen;
    while(! defined ($err = sysread($runnerr, $datalen, 4)) || $err <= 0) {
        if((!defined $err && ! $!{EINTR}) || (defined $err && $err == 0)) {
            # pipe has closed; controller is gone and we must exit
            runnerabort();
            # Special case: no response will be forthcoming
            return 1;
        }
        # system call was interrupted, probably by ^C; restart it so we stay in sync
    }
    my $len=unpack("L", $datalen);
    my $buf;
    while(! defined ($err = sysread($runnerr, $buf, $len)) || $err <= 0) {
        if((!defined $err && ! $!{EINTR}) || (defined $err && $err == 0)) {
            # pipe has closed; controller is gone and we must exit
            runnerabort();
            # Special case: no response will be forthcoming
            return 1;
        }
        # system call was interrupted, probably by ^C; restart it so we stay in sync
    }

    # Decode the function name and arguments
    my $argsarrayref = thaw $buf;

    # The name of the function to call is the first argument
    my $funcname = shift @$argsarrayref;

    # print "ipcrecv $funcname\n";
    # Synchronously call the desired function
    my @res;
    if($funcname eq "runner_clearlocks") {
        @res = runner_clearlocks(@$argsarrayref);
    }
    elsif($funcname eq "runner_shutdown") {
        runner_shutdown(@$argsarrayref);
        # Special case: no response will be forthcoming
        return 1;
    }
    elsif($funcname eq "runner_stopservers") {
        @res = runner_stopservers(@$argsarrayref);
    }
    elsif($funcname eq "runner_test_preprocess") {
        @res = runner_test_preprocess(@$argsarrayref);
    }
    elsif($funcname eq "runner_test_run") {
        @res = runner_test_run(@$argsarrayref);
    } else {
        die "Unknown IPC function $funcname\n";
    }
    # print "ipcrecv results\n";

    # Marshall the results to return
    $buf = freeze \@res;

    while(! defined ($err = syswrite($runnerw, (pack "L", length($buf)) . $buf)) || $err <= 0) {
        if((!defined $err && ! $!{EINTR}) || (defined $err && $err == 0)) {
            # pipe has closed; controller is gone and we must exit
            runnerabort();
            # Special case: no response will be forthcoming
            return 1;
        }
        # system call was interrupted, probably by ^C; restart it so we stay in sync
    }

    return 0;
}

###################################################################
# Kill the server processes that still have lock files in a directory
sub runner_clearlocks {
    my ($lockdir)=@_;
    if(clearlogs()) {
        logmsg "Warning: log messages were lost\n";
    }
    clearlocks($lockdir);
    return clearlogs();
}


###################################################################
# Kill all server processes
sub runner_stopservers {
    my $error = stopservers($verbose);
    my $logs = clearlogs();
    return ($error, $logs);
}

###################################################################
# Shut down this runner
sub runner_shutdown {
    close($runnerr);
    undef $runnerr;
    close($runnerw);
    undef $runnerw;
}


1;
