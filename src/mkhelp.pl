#!/usr/local/bin/perl

# Yeah, I know, probably 1000 other persons already wrote a script like
# this, but I'll tell ya:

# THEY DON'T FIT ME :-)

# Get readme file as parameter:
$README = $ARGV[0];

if($README eq "") {
    print "usage: mkreadme.pl <README>\n";
    exit;
}


push @out, "                                  _   _ ____  _     \n";
push @out, "  Project                     ___| | | |  _ \\| |    \n";
push @out, "                             / __| | | | |_) | |    \n";
push @out, "                            | (__| |_| |  _ <| |___ \n";
push @out, "                             \\___|\\___/|_| \\_\\_____|\n";

$head=0;
loop:
while (<STDIN>) {
    $line = $_;

    # this kind should be removed first:
    $line =~ s/_//g;

    # then this:
    $line =~ s/.//g;

    if($line =~ /^curl/i) {
	# cut off the page headers
        $head=1;
	next loop;
    } 

    if($line =~ /^[ \t]*\n/) {
	$wline++;
	# we only make one empty line max
	next loop;
    }
    if($wline) {
	$wline = 0;
        if(!$head) {
            push @out, "\n";
        }
        $head =0;
    }
    push @out, $line;
}
push @out, "\n"; # just an extra newline

open(READ, "<$README") ||
    die "couldn't read the README infile";

while(<READ>) {
    push @out, $_;
}
close(READ);


print "/* NEVER EVER edit this manually, fix the mkhelp script instead! */\n"
;
print "#include <stdio.h>\n";
print "void hugehelp(void)\n";
print "{\n";
print "puts (\n";

for(@out) {
    chop;

    $new = $_;

    $new =~ s/\\/\\\\/g;
    $new =~ s/\"/\\\"/g;

    printf("\"%s\\n\"\n", $new);

}

print " ) ;\n}\n"
    
