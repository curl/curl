#!/usr/bin/env perl
# Check that given arguments do not exist on filesystem.
my $code = 0;
if ($#ARGV < 0) {
    print "Usage: $0 file1 [fileN]\n";
    exit 2;
}
while (@ARGV) {
    my $fname = shift @ARGV;
    if (-e $fname) {
        print "Found '$fname' when not supposed to exist.\n";
        $code = 1;
    }
}
exit $code;
