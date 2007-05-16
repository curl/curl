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
    	utime time, timegm(0,0,12,1,0,100), "plainfile.txt";
    	chmod 0666, "plainfile.txt";

	open(FILE, ">rofile.txt") || errout "$!";
	binmode FILE;
	print FILE "Read-only test file to support curl test suite\n";
    	close(FILE);
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
		# Process the directory file to remove all information that could
		# be inconsistent from one test run to the next (e.g. file date)
		# or may be unsupported on some platforms (e.g. Windows)

		my $newfile = $logfile . ".new";
		open(IN, "<$logfile") || die "$!";
		open(OUT, ">$newfile") || die "$!";
		while (<IN>) {
			s/^(.)(..).(..).(..).(.{4}?).{6}?.{6}?(.{12}?)/\1\2?\3?\4?\5     U     U\6/;
			if ($1 eq "d") {
				# Erase inodes, size, mode, time fields for directories
				s/^.{14}?(.{12}?).{11}? ... .\d .\d:\d\d/d?????????   N\1          N ???  N NN:NN/;
			}
			print OUT $_;
		}

		close(OUT);
		close(IN);

		unlink $logfile;
		rename $newfile, $logfile;
	}

	exit 0;
}
print "Unsupported command $ARGV[0]\n";
exit 1;
