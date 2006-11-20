#***************************************************************************
#                                  _   _ ____  _
#  Project                     ___| | | |  _ \| |
#                             / __| | | | |_) | |
#                            | (__| |_| |  _ <| |___
#                             \___|\___/|_| \_\_____|
#
# Copyright (C) 1998 - 2006, Daniel Stenberg, <daniel@haxx.se>, et al.
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

use strict;
#use warnings; # requires perl 5.006 or later


my $DEFAULT_TIMEOUT_START = 90; # default allowed time for a process to startup
my $DEFAULT_TIMEOUT_STOP  = 90; # default allowed time for a process to stop

my $ONE_HALF_STOP_TIMEOUT  = int($DEFAULT_TIMEOUT_STOP / 2);
my $ONE_THIRD_STOP_TIMEOUT = int($DEFAULT_TIMEOUT_STOP / 3);
my $ONE_SIXTH_STOP_TIMEOUT = int($DEFAULT_TIMEOUT_STOP / 6);

my $pidpattern = qr/^\-?(\d+)$/; # pre-compiled pid pattern regexp


######################################################################
# pidfromfile returns the pid stored in the given pidfile.  The value
# of the returned pid will never be a negative value. It will be zero
# on any file related error or if a pid can not be extracted from the
# file. Otherwise it will be a positive value, even If the pid number
# stored in the file is a negative one.
#
sub pidfromfile {
    my ($pidfile)=@_;

    my $pid = 0; # on failure or empty file return 0
    my $pidline;

    if(not defined $pidfile) {
        return 0;
    }
    if(-f $pidfile) {
        if(open(PIDF, "<$pidfile")) {
            my $pidline = <PIDF>;
            close(PIDF);
            if($pidline) {
                chomp $pidline;
                $pidline =~ s/^\s+//;
                $pidline =~ s/\s+$//;
                $pidline =~ s/^[+-]?0+//;
                if($pidline =~ $pidpattern) {
                    $pid = $1;
                }
            }
        }
    }
    return $pid;
}


######################################################################
# unlinkpidfiles unlinks/deletes the given pidfiles. The first argument
# 'pidfiles' is a string of whitespace separated pidfiles. If successful
# returns 0, on error it returns the number of files not deleted.
#
sub unlinkpidfiles {
    my ($pidfiles)=@_;

    if(not defined $pidfiles) {
        return 0;
    }
    my $pidfile;
    my $errcount = 0;
    for $pidfile (split(" ", $pidfiles)) {
        if($pidfile) {
            if(unlink($pidfile) == 0) {
                $errcount++;
            }
        }
    }
    return $errcount;
}


######################################################################
# checkalivepid checks if the process of the given pid is alive. The
# argument must represent a single pid and be a valid number, if not
# it will return 0. It will also return 0 if the pid argument is zero
# or negative. If the pid argument is positive and it is alive returns
# the same positive pid, otherwise, if it is not alive it will return
# the negative value of the pid argument.
#
sub checkalivepid {
    my ($pid)=@_;

    if(not defined $pid) {
        return 0;
    }
    if ($pid !~ $pidpattern) {
        return 0; # invalid argument
    }
    if($pid > 0) {
        if(kill(0, $pid)) {
            return $pid; # positive means it is alive
        }
        else {
            return -$pid; # negative means dead process
        }
    }
    return 0; # not a positive pid argument
}


######################################################################
# checkalivepidfile checks if the process of the pid stored in the
# given pidfile is alive. It will return 0 on any file related error
# or if a pid can not be extracted from the file. If the process of
# the pid present in the file is alive it returns that positive pid,
# if it is not alive it will return the negative value of the pid.
#
sub checkalivepidfile {
    my ($pidfile)=@_;

    my $pid = pidfromfile($pidfile);
    my $ret = checkalivepid($pid);
    return $ret;
}


######################################################################
# signalpids signals processes in the second argument with the signal
# given in the first argument. The second argument 'pids' is a string
# of whitespace separated pids. Of the given pids only those that are
# positive and are actually alive will be signalled, and no matter
# how many times a pid is repeated it will only be signalled once.
#
sub signalpids {
    my ($signal, $pids, $verbose)=@_;

    if((not defined $signal) || (not defined $pids)) {
        return;
    }
    if($pids !~ /\s+/) {
        # avoid sorting if only one pid
        if(checkalivepid($pids) > 0) {
            printf ("* pid $pids signalled ($signal)\n") if($verbose);
            kill($signal, $pids);
        }
        return;
    }
    my $prev = 0;
    for(sort({$a <=> $b} split(" ", $pids))) {
        if($_ =~ $pidpattern) {
            my $pid = $1;
            if($prev != $pid) {
                $prev = $pid;
                if(checkalivepid($pid) > 0) {
                    printf ("* pid $pid signalled ($signal)\n") if($verbose);
                    kill($signal, $pid);
                }
            }
        }
    }
}


######################################################################
# signalpidfile signals the process of the pid stored in the given
# pidfile with the signal given in the first argument if the process
# with that pid is actually alive.
#
sub signalpidfile {
    my ($signal, $pidfile, $verbose)=@_;

    my $pid = pidfromfile($pidfile);
    if($pid > 0) {
        signalpids($signal, $pid, $verbose);
    }
}

    
######################################################################
# waitdeadpid waits until all processes given in the first argument
# are not alive, waiting at most timeout seconds. The first argument
# 'pids' is a string of whitespace separated pids. Returns 1 when all
# pids are not alive. Returns 0 when the specified timeout has expired
# and at least one of the specified pids is still alive.
#
sub waitdeadpid {
    my ($pids, $timeout)=@_;

    if(not defined $pids) {
        return 1;
    }
    if((not defined $timeout) || ($timeout < 1)) {
        $timeout = $DEFAULT_TIMEOUT_STOP;
    }
    while($timeout--) {
        my $alive = 0;
        for(split(" ", $pids)) {
            if($_ =~ $pidpattern) {
                my $pid = $1;
                if(checkalivepid($pid) > 0) {
                    $alive++;
                }
            }
        }
        if($alive == 0) {
            return 1; # not a single pid is alive
        }
        sleep(1);
    }
    return 0; # at least one pid is still alive after timeout seconds
}


######################################################################
# waitalivepidfile waits until the given pidfile has a pid that is
# alive, waiting at most timeout seconds. It returns the positive pid
# When it is alive, otherwise it returns 0 when timeout seconds have
# elapsed and the pidfile does not have a pid that is alive.
#
sub waitalivepidfile {
    my ($pidfile, $timeout)=@_;

    if(not defined $pidfile) {
        return 0;
    }
    if((not defined $timeout) || ($timeout < 1)) {
        $timeout = $DEFAULT_TIMEOUT_START;
    }
    while($timeout--) {
        my $pid = checkalivepidfile($pidfile);
        if($pid > 0) {
            return $pid; # positive means it is alive
        }
        sleep(1);
    }
    return 0; # no pid in pidfile or not alive
}


######################################################################
# stopprocess ends the given pid(s), waiting for them to die. The 'pids'
# argument is a string of whitespace separated pids. Returns 1 if all
# of the processes have been successfully stopped. If unable to stop
# any of them in DEFAULT_TIMEOUT_STOP seconds then it returns 0.
#
sub stopprocess {
    my ($pids, $verbose)=@_;

    if(not defined $pids) {
        return 1;
    }
    signalpids("KILL", $pids, $verbose);
    if(waitdeadpid($pids, $ONE_HALF_STOP_TIMEOUT) == 0) {
        signalpids("KILL", $pids, $verbose);
        if(waitdeadpid($pids, $ONE_THIRD_STOP_TIMEOUT) == 0) {
            signalpids("KILL", $pids, $verbose);
            if(waitdeadpid($pids, $ONE_SIXTH_STOP_TIMEOUT) == 0) {
                return 0; # at least one pid is still alive !!!
            }
        }
    }
    return 1; # not a single pid is alive
}


######################################################################
# stopprocesspidfile ends the test server process of the given pidfile,
# waiting for it to die, and unlinking/deleting the given pidfile. If
# the given process was not running or has been successfully stopped it
# returns 1. If unable to stop it in DEFAULT_TIMEOUT_STOP seconds then
# returns 0.
#
sub stopprocesspidfile {
    my ($pidfile, $verbose)=@_;

    if(not defined $pidfile) {
        return 1;
    }
    my $ret = 1; # assume success stopping it
    my $pid = checkalivepidfile($pidfile);
    if($pid > 0) {
        $ret = stopprocess($pid, $verbose);
    }
    unlinkpidfiles($pidfile);
    return $ret;
}


######################################################################
# ftpkillslave ends a specific slave, waiting for it to die, and
# unlinking/deleting its pidfiles. If the given ftpslave was not
# running or has been successfully stopped it returns 1. If unable
# to stop it in DEFAULT_TIMEOUT_STOP seconds then it returns 0.
#
sub ftpkillslave {
    my ($id, $ext, $verbose)=@_;

    if(not defined $id) {
        $id = "";
    }
    if(not defined $ext) {
        $ext = "";
    }
    my $ret = 1; # assume success stopping them
    my $pids = "";
    my $pidfiles = "";
    for my $base (('filt', 'data')) {
        my $pidfile = ".sock$base$id$ext.pid";
        my $pid = checkalivepidfile($pidfile);
        $pidfiles .= " $pidfile";
        if($pid > 0) {
            $pids .= " $pid";
        }
    }
    if($pids) {
        $ret = stopprocess($pids, $verbose);
    }
    if($pidfiles) {
        unlinkpidfiles($pidfiles);
    }
    return $ret;
}


######################################################################
# ftpkillslaves ends all the ftpslave processes, waiting for them to
# die, unlinking/deleting its pidfiles. If they were not running or
# have been successfully stopped it returns 1. If unable to stop any
# of them in DEFAULT_TIMEOUT_STOP seconds then returns 0.
#
sub ftpkillslaves {
    my ($verbose)=@_;

    my $ret = 1; # assume success stopping them
    my $pids = "";
    my $pidfiles = "";
    for my $ext (("", "ipv6")) {
        for my $id (("", "2")) {
            for my $base (('filt', 'data')) {
                my $pidfile = ".sock$base$id$ext.pid";
                my $pid = checkalivepidfile($pidfile);
                $pidfiles .= " $pidfile";
                if($pid > 0) {
                    $pids .= " $pid";
                }
            }
        }
    }
    if($pids) {
        $ret = stopprocess($pids, $verbose);
    }
    if($pidfiles) {
        unlinkpidfiles($pidfiles);
    }
    return $ret;
}


######################################################################
# library files end with 1; to make 'require' and 'use' succeed.
1;

