#!/usr/bin/perl

# pass files as argument(s)

my $docroot="http://curl.haxx.se/libcurl/c";

for $f (@ARGV) {
    open(NEW, ">$f.new");
    open(F, "<$f");
    while(<F>) {
        my $l = $_;
        if($l =~ /\/* $docroot/) {
            # just ignore preciously added refs
        }
        elsif($l =~ /^( *).*curl_easy_setopt\([^,]*, *([^ ,]*) *,/) {
            my ($prefix, $anc) = ($1, $2);
            $anc =~ s/_//g;
            print NEW "$prefix/* $docroot/curl_easy_setopt.html#$anc */\n";
            print NEW $l;
        }
        elsif($l =~ /^( *).*(curl_([^\(]*))\(/) {
            my ($prefix, $func) = ($1, $2);
            print NEW "$prefix/* $docroot/$func.html */\n";
            print NEW $l;
        }
        else {
            print NEW $l;
        }
    }
    close(F);
    close(NEW);

    system("mv $f $f.org");
    system("mv $f.new $f");
}
