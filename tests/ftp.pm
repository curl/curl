# make sure no leftovers are still running
sub ftpkillslaves {
    for $ext (("", "ipv6")) {
        for $id (("", "2")) {
            for $base (('filt', 'data')) {
                my $f = ".sock$base$id$ext.pid";
                my $pid = checkserver($f);
                if($pid > 0) {
		    printf ("* kill pid for %-5s => %-5d\n", "ftp-$base$id$ext", $pid);
                    kill (9, $pid); # die!
                }
                unlink($f);
            }
        }
    }
}

1;
