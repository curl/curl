#!/usr/bin/env perl
# Create and remove directories and check their existence
if ( $#ARGV != 1 ) 
{
	print "Usage: $0 mkdir|rmdir|gone path\n";
	exit 1;
}
if ($ARGV[0] eq "mkdir")
{
	mkdir $ARGV[1] || die "$!";
	exit 0;
}
elsif ($ARGV[0] eq "rmdir")
{
	rmdir $ARGV[1] || die "$!";
	exit 0;
}
elsif ($ARGV[0] eq "gone")
{
	! -e $ARGV[1] || die "Path $ARGV[1] exists";
	exit 0;
}
print "Unsupported command $ARGV[0]\n";
exit 1;
