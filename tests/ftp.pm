#***************************************************************************
#                                  _   _ ____  _
#  Project                     ___| | | |  _ \| |
#                             / __| | | | |_) | |
#                            | (__| |_| |  _ <| |___
#                             \___|\___/|_| \_\_____|
#
# Copyright (C) 1998 - 2009, Daniel Stenberg, <daniel@haxx.se>, et al.
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

#######################################################################
# pidfromfile returns the pid stored in the given pidfile.  The value
# of the returned pid will never be a negative value. It will be zero
# on any file related error or if a pid can not be extracted from the
# given file.
#
sub pidfromfile {
    my $pidfile = $_[0];
    my $pid = 0;

    if(-f $pidfile && -s $pidfile && open(PIDFH, "<$pidfile")) {
        $pid = 0 + <PIDFH>;
        close(PIDFH);
        $pid = 0 unless($pid > 0);
    }
    return $pid;
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
#   use POSIX ":sys_wait_h";
    my $pidfile = $_[0];

    # fetch pid from pidfile
    my $pid = pidfromfile($pidfile);

    if($pid > 0) {
        # verify if currently alive
        if(kill(0, $pid)) {
            return $pid;
        }
        else {
            # reap it if this has not already been done
            # waitpid($pid, &WNOHANG);
            # get rid of the certainly invalid pidfile
            unlink($pidfile) if($pid == pidfromfile($pidfile));
            return -$pid; # negative means dead process
        }
    }
    return 0;
}

#############################################################################
# Kill a specific slave
#
sub ftpkillslave {
    my ($id, $ext, $verbose)=@_;
    my $base;
    for $base (('filt', 'data')) {
        my $f = ".sock$base$id$ext.pid";
        my $pid = processexists($f);
        if($pid > 0) {
            printf ("* kill pid for %s => %d\n", "ftp-$base$id$ext", $pid) if($verbose);
            kill (9, $pid); # die!
            waitpid($pid, 0);
        }
        unlink($f);
    }
}


#############################################################################
# Make sure no FTP leftovers are still running. Kill all slave processes.
# This uses pidfiles since it might be used by other processes.
#
sub ftpkillslaves {
    my ($versbose) = @_;
    for $ext (("", "ipv6")) {
        for $id (("", "2")) {
            ftpkillslave ($id, $ext, $verbose);
        }
    }
}


sub set_advisor_read_lock {
    my ($filename) = @_;

    if(open(FILEH, ">$filename")) {
        close(FILEH);
        return;
    }
    printf "Error creating lock file $filename error: $!";
}


sub clear_advisor_read_lock {
    my ($filename) = @_;

    if(-f $filename) {
        unlink($filename);
    }
}


1;
