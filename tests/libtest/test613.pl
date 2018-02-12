#!/usr/bin/env perl
# Prepare a directory with known files and clean up afterwards
use Time::Local;

if ( $#ARGV < 1 )
{
    print "Usage: $0 prepare|postprocess dir [logfile]\n";
    exit 1;
}

# <precheck> expects an error message on stdout
sub errout {
    print $_[0] . "\n";
    exit 1;
}

if ($ARGV[0] eq "prepare")
{
    my $dirname = $ARGV[1];
    mkdir $dirname || errout "$!";
    chdir $dirname;

    # Create the files in alphabetical order, to increase the chances
    # of receiving a consistent set of directory contents regardless
    # of whether the server alphabetizes the results or not.
    mkdir "asubdir" || errout "$!";
    chmod 0777, "asubdir";

    open(FILE, ">plainfile.txt") || errout "$!";
    binmode FILE;
    print FILE "Test file to support curl test suite\n";
    close(FILE);
    # The mtime is specifically chosen to be an even number so that it can be
    # represented exactly on a FAT filesystem.
    utime time, timegm(0,0,12,1,0,100), "plainfile.txt";
    chmod 0666, "plainfile.txt";

    open(FILE, ">rofile.txt") || errout "$!";
    binmode FILE;
    print FILE "Read-only test file to support curl test suite\n";
    close(FILE);
    # The mtime is specifically chosen to be an even number so that it can be
    # represented exactly on a FAT filesystem.
    utime time, timegm(0,0,12,31,11,100), "rofile.txt";
    chmod 0444, "rofile.txt";

    exit 0;
}
elsif ($ARGV[0] eq "postprocess")
{
    my $dirname = $ARGV[1];
    my $logfile = $ARGV[2];

    # Clean up the test directory
    unlink "$dirname/rofile.txt";
    unlink "$dirname/plainfile.txt";
    rmdir "$dirname/asubdir";

    rmdir $dirname || die "$!";

    if ($logfile) {
        # Process the directory file to remove all information that
        # could be inconsistent from one test run to the next (e.g.
        # file date) or may be unsupported on some platforms (e.g.
        # Windows). Also, since 7.17.0, the sftp directory listing
        # format can be dependent on the server (with a recent
        # enough version of libssh2) so this script must also
        # canonicalize the format.  Here are examples of the general
        # format supported:
        # -r--r--r--   12 ausername grp            47 Dec 31  2000 rofile.txt
        # -r--r--r--   1  1234  4321         47 Dec 31  2000 rofile.txt
        # The "canonical" format is similar to the first (which is
        # the one generated on a typical Linux installation):
        # -r-?r-?r-?   12 U         U              47 Dec 31  2000 rofile.txt

        my @canondir;
        open(IN, "<$logfile") || die "$!";
        while (<IN>) {
            /^(.)(..).(..).(..).\s*(\S+)\s+\S+\s+\S+\s+(\S+)\s+(\S+\s+\S+\s+\S+)(.*)$/;
            if ($1 eq "d") {
                # Erase all directory metadata except for the name, as it is not
                # consistent for across all test systems and filesystems
                push @canondir, "d?????????    N U         U               N ???  N NN:NN$8\n";
            } elsif ($1 eq "-") {
                # Erase user and group names, as they are not consistent across
                # all test systems
                my $line = sprintf("%s%s?%s?%s?%5d U         U %15d %s%s\n", $1,$2,$3,$4,$5,$6,$7,$8);
                push @canondir, $line;
            } else {
                # Unexpected format; just pass it through and let the test fail
                push @canondir, $_;
            }
        }
        close(IN);

        @canondir = sort {substr($a,57) cmp substr($b,57)} @canondir;
        my $newfile = $logfile . ".new";
        open(OUT, ">$newfile") || die "$!";
        print OUT join('', @canondir);
        close(OUT);

        unlink $logfile;
        rename $newfile, $logfile;
    }

    exit 0;
}
print "Unsupported command $ARGV[0]\n";
exit 1;
