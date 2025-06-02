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

package processhelp;

use strict;
use warnings;

BEGIN {
    use base qw(Exporter);

    our @EXPORT = qw(
        portable_sleep
        pidfromfile
        pidexists
        pidwait
        processexists
        killpid
        killsockfilters
        killallsockfilters
        set_advisor_read_lock
        clear_advisor_read_lock
    );

    # portable sleeping needs Time::HiRes
    eval {
        no warnings "all";
        require Time::HiRes;
    };
    # portable sleeping falls back to native Sleep on Windows
    eval {
        no warnings "all";
        require Win32;
    }
}

use serverhelp qw(
    servername_id
    mainsockf_pidfilename
    datasockf_pidfilename
    );

use pathhelp qw(
    os_is_win
    );

#######################################################################
# portable_sleep uses Time::HiRes::sleep if available and falls back
# to the classic approach of using select(undef, undef, undef, ...).
# even though that one is not portable due to being implemented using
# select on Windows: https://perldoc.perl.org/perlport.html#select
# Therefore it uses Win32::Sleep on Windows systems instead.
#
sub portable_sleep {
    my ($seconds) = @_;

    if($Time::HiRes::VERSION) {
        Time::HiRes::sleep($seconds);
    }
    elsif (os_is_win()) {
        Win32::Sleep($seconds*1000);
    }
    else {
        select(undef, undef, undef, $seconds);
    }
}

#######################################################################
# pidfromfile returns the pid stored in the given pidfile.  The value
# of the returned pid will never be a negative value. It will be zero
# on any file related error or if a pid can not be extracted from the
# given file.
#
sub pidfromfile {
    my $pidfile = $_[0];
    my $timeout_sec = $_[1];
    my $pid = 0;
    my $waits = 0;
    # wait at max 15 seconds for the file to exist and have valid content
    while(!$pid && ($waits <= ($timeout_sec * 10))) {
        if(-f $pidfile && -s $pidfile && open(my $pidfh, "<", "$pidfile")) {
            $pid = 0 + <$pidfh>;
            close($pidfh);
            $pid = 0 if($pid < 0);
        }
        Time::HiRes::sleep(0.1) unless $pid || !$timeout_sec;
        ++$waits;
    }
    return $pid;
}

#######################################################################
# return Cygwin pid from virtual pid
#
sub winpid_to_pid {
    my $vpid = $_[0];
    if(($^O eq 'cygwin' || $^O eq 'msys') && $vpid > 4194304) {
        my $pid = Cygwin::winpid_to_pid($vpid - 4194304);
        if($pid) {
            return $pid;
        } else {
            return $vpid
        }
    }
    return $vpid;
}

#######################################################################
# pidexists checks if a process with a given pid exists and is alive.
# This will return the positive pid if the process exists and is alive.
# This will return the negative pid if the process exists differently.
# This will return 0 if the process could not be found.
#
sub pidexists {
    my $pid = $_[0];

    if($pid > 0) {
        # verify if currently existing Windows process
        $pid = winpid_to_pid($pid);
        if ($pid > 4194304 && os_is_win()) {
            $pid -= 4194304;
            if($^O ne 'MSWin32') {
                my $filter = "PID eq $pid";
                # https://ss64.com/nt/tasklist.html
                my $result = `tasklist -fi \"$filter\" 2>nul`;
                if(index($result, "$pid") != -1) {
                    return -$pid;
                }
                return 0;
            }
        }

        # verify if currently existing and alive
        if(kill(0, $pid)) {
            return $pid;
        }
    }

    return 0;
}

#######################################################################
# pidterm asks the process with a given pid to terminate gracefully.
#
sub pidterm {
    my $pid = $_[0];

    if($pid > 0) {
        # request the process to quit
        $pid = winpid_to_pid($pid);
        if ($pid > 4194304 && os_is_win()) {
            $pid -= 4194304;
            if($^O ne 'MSWin32') {
                # https://ss64.com/nt/taskkill.html
                my $cmd = "taskkill -f -t -pid $pid >nul 2>&1";
                print "Executing: '$cmd'\n";
                system($cmd);
                return;
            }
        }

        # signal the process to terminate
        kill("TERM", $pid);
    }
}

#######################################################################
# pidkill kills the process with a given pid mercilessly and forcefully.
#
sub pidkill {
    my $pid = $_[0];

    if($pid > 0) {
        # request the process to quit
        $pid = winpid_to_pid($pid);
        if ($pid > 4194304 && os_is_win()) {
            $pid -= 4194304;
            if($^O ne 'MSWin32') {
                # https://ss64.com/nt/taskkill.html
                my $cmd = "taskkill -f -t -pid $pid >nul 2>&1";
                print "Executing: '$cmd'\n";
                system($cmd);
                return;
            }
        }

        # signal the process to terminate
        kill("KILL", $pid);
    }
}

#######################################################################
# pidwait waits for the process with a given pid to be terminated.
#
sub pidwait {
    my $pid = $_[0];
    my $flags = $_[1];

    $pid = winpid_to_pid($pid);
    # check if the process exists
    if ($pid > 4194304 && os_is_win()) {
        if($flags == &WNOHANG) {
            return pidexists($pid)?0:$pid;
        }
        my $start = time;
        my $warn_at = 5;
        while(pidexists($pid)) {
            if(time - $start > $warn_at) {
                print "pidwait: still waiting for PID ", $pid, "\n";
                $warn_at += 5;
                if($warn_at > 20) {
                    print "pidwait: giving up waiting for PID ", $pid, "\n";
                    last;
                }
            }
            portable_sleep(0.2);
        }
        return $pid;
    }

    # wait on the process to terminate
    return waitpid($pid, $flags);
}

#######################################################################
# processexists checks if a process with the pid stored in the given
# pidfile exists and is alive. This will return 0 on any file related
# error or if a pid can not be extracted from the given file. When a
# process with the same pid as the one extracted from the given file
# is currently alive this returns that positive pid. Otherwise, when
# the process is not alive, will return the negative value of the pid.
#
sub processexists {
    use POSIX ":sys_wait_h";
    my $pidfile = $_[0];

    # fetch pid from pidfile
    my $pid = pidfromfile($pidfile, 0);

    if($pid > 0) {
        # verify if currently alive
        if(pidexists($pid)) {
            return $pid;
        }
        else {
            # get rid of the certainly invalid pidfile
            unlink($pidfile) if($pid == pidfromfile($pidfile, 0));
            # reap its dead children, if not done yet
            pidwait($pid, &WNOHANG);
            # negative return value means dead process
            return -$pid;
        }
    }
    return 0;
}

#######################################################################
# killpid attempts to gracefully stop processes in the given pid list
# with a SIGTERM signal and SIGKILLs those which haven't died on time.
#
sub killpid {
    my ($verbose, $pidlist) = @_;
    use POSIX ":sys_wait_h";
    my @requested;
    my @signalled;
    my @reapchild;

    # The 'pidlist' argument is a string of whitespace separated pids.
    return if(not defined($pidlist));

    # Make 'requested' hold the non-duplicate pids from 'pidlist'.
    @requested = split(' ', $pidlist);
    return if(not @requested);
    if(scalar(@requested) > 2) {
        @requested = sort({$a <=> $b} @requested);
    }
    for(my $i = scalar(@requested) - 2; $i >= 0; $i--) {
        if($requested[$i] == $requested[$i+1]) {
            splice @requested, $i+1, 1;
        }
    }

    # Send a SIGTERM to processes which are alive to gracefully stop them.
    foreach my $tmp (@requested) {
        chomp $tmp;
        if($tmp =~ /^(\d+)$/) {
            my $pid = $1;
            if($pid > 0) {
                if(pidexists($pid)) {
                    print("RUN: Process with pid $pid signalled to die\n")
                        if($verbose);
                    pidterm($pid);
                    push @signalled, $pid;
                }
                else {
                    print("RUN: Process with pid $pid already dead\n")
                        if($verbose);
                    # if possible reap its dead children
                    pidwait($pid, &WNOHANG);
                    push @reapchild, $pid;
                }
            }
        }
    }

    # Allow all signalled processes five seconds to gracefully die.
    if(@signalled) {
        my $twentieths = 5 * 20;
        while($twentieths--) {
            for(my $i = scalar(@signalled) - 1; $i >= 0; $i--) {
                my $pid = $signalled[$i];
                if(!pidexists($pid)) {
                    print("RUN: Process with pid $pid gracefully died\n")
                        if($verbose);
                    splice @signalled, $i, 1;
                    # if possible reap its dead children
                    pidwait($pid, &WNOHANG);
                    push @reapchild, $pid;
                }
            }
            last if(not scalar(@signalled));
            # give any zombies of us a chance to move on to the afterlife
            pidwait(0, &WNOHANG);
            portable_sleep(0.05);
        }
    }

    # Mercilessly SIGKILL processes still alive.
    if(@signalled) {
        foreach my $pid (@signalled) {
            if($pid > 0) {
                print("RUN: Process with pid $pid forced to die with SIGKILL\n")
                    if($verbose);
                pidkill($pid);
                # if possible reap its dead children
                pidwait($pid, &WNOHANG);
                push @reapchild, $pid;
            }
        }
    }

    # Reap processes dead children for sure.
    if(@reapchild) {
        foreach my $pid (@reapchild) {
            if($pid > 0) {
                pidwait($pid, 0);
            }
        }
    }
}

#######################################################################
# killsockfilters kills sockfilter processes for a given server.
#
sub killsockfilters {
    my ($piddir, $proto, $ipvnum, $idnum, $verbose, $which) = @_;
    my $server;
    my $pidfile;
    my $pid;

    return if($proto !~ /^(ftp|imap|pop3|smtp)$/);

    die "unsupported sockfilter: $which"
        if($which && ($which !~ /^(main|data)$/));

    $server = servername_id($proto, $ipvnum, $idnum) if($verbose);

    if(!$which || ($which eq 'main')) {
        $pidfile = mainsockf_pidfilename($piddir, $proto, $ipvnum, $idnum);
        $pid = processexists($pidfile);
        if($pid > 0) {
            printf("* kill pid for %s-%s => %d\n", $server,
                ($proto eq 'ftp')?'ctrl':'filt', $pid) if($verbose);
            pidkill($pid);
            pidwait($pid, 0);
        }
        unlink($pidfile) if(-f $pidfile);
    }

    return if($proto ne 'ftp');

    if(!$which || ($which eq 'data')) {
        $pidfile = datasockf_pidfilename($piddir, $proto, $ipvnum, $idnum);
        $pid = processexists($pidfile);
        if($pid > 0) {
            printf("* kill pid for %s-data => %d\n", $server,
                $pid) if($verbose);
            pidkill($pid);
            pidwait($pid, 0);
        }
        unlink($pidfile) if(-f $pidfile);
    }
}

#######################################################################
# killallsockfilters kills sockfilter processes for all servers.
#
sub killallsockfilters {
    my ($piddir, $verbose) = @_;

    for my $proto (('ftp', 'imap', 'pop3', 'smtp')) {
        for my $ipvnum (('4', '6')) {
            for my $idnum (('1', '2')) {
                killsockfilters($piddir, $proto, $ipvnum, $idnum, $verbose);
            }
        }
    }
}


sub set_advisor_read_lock {
    my ($filename) = @_;

    my $fileh;
    if(open($fileh, ">", "$filename") && close($fileh)) {
        return;
    }
    printf "Error creating lock file $filename error: $!\n";
}


sub clear_advisor_read_lock {
    my ($filename) = @_;

    if(-f $filename) {
        unlink($filename);
    }
}


1;
