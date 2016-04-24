#!/usr/bin/env perl
# Perform simple file and directory manipulation in a portable way
if ( $#ARGV <= 0 )
{
    print "Usage: $0 mkdir|rmdir|rm|move|gone path1 [path2] [more commands...]\n";
    exit 1;
}

use File::Copy;
while(@ARGV) {
    my $cmd = shift @ARGV;
    my $arg = shift @ARGV;
    if ($cmd eq "mkdir") {
        mkdir $arg || die "$!";
    }
    elsif ($cmd eq "rmdir") {
        rmdir $arg || die "$!";
    }
    elsif ($cmd eq "rm") {
        unlink $arg || die "$!";
    }
    elsif ($cmd eq "move") {
        my $arg2 = shift @ARGV;
        move($arg,$arg2) || die "$!";
    }
    elsif ($cmd eq "gone") {
        ! -e $arg || die "Path $arg exists";
    } else {
        print "Unsupported command $cmd\n";
        exit 1;
    }
}
exit 0;
