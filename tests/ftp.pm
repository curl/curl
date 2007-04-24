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

#######################################################################
# Return the pid of the server as found in the given pid file
#
sub serverpid {
    my $PIDFILE = $_[0];
    open(PFILE, "<$PIDFILE");
    my $PID=0+<PFILE>;
    close(PFILE);
    return $PID;
}

#######################################################################
# Check the given test server if it is still alive.
#
sub checkserver {
    my ($pidfile)=@_;
    my $pid=0;

    # check for pidfile
    if ( -f $pidfile ) {
        $pid=serverpid($pidfile);
        if ($pid ne "" && kill(0, $pid)) {
            return $pid;
        }
        else {
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
        my $pid = checkserver($f);
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

1;
