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
# Make sure no FTP leftovers are still running. Kill all slave processes.
# This uses pidfiles since it might be used by other processes.
#
sub ftpkillslaves {
    my ($versbose) = @_;
    for $ext (("", "ipv6")) {
        for $id (("", "2")) {
            for $base (('filt', 'data')) {
                my $f = ".sock$base$id$ext.pid";
                my $pid = checkserver($f);
                if($pid > 0) {
		    printf ("* kill pid for %-5s => %-5d\n", "ftp-$base$id$ext", $pid) if($verbose);
                    kill (9, $pid); # die!
                }
                unlink($f);
            }
        }
    }
}

1;
