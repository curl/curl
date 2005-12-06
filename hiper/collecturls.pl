#!/usr/bin/perl

# 1) http://randomurl.com/body.php
# 2) http://random.yahoo.com/fast/ryl
# 3) http://www.uroulette.com/visit

# 1) very slow, responds with URL in body meta style:
# <meta http-equiv="refresh" content="0; url=http://www.webmasterworld.com/forum85/735.htm">

# 2) Responds with non-HTTP headers like:
# Status: 301
# Location: http://www.adaptive.net/

# 3) ordinary 30X code and Location:

my $url;
map { $url .= " http://www.uroulette.com/visit"; } (1 .. 12);

print $url."\n";

my $count=0;

open(DUMP, ">>dump");

while(1) {
    my @getit = `curl -si $url`;
    for my $l (@getit) {
        if($l =~ /^Location: (.*)/) {
            print DUMP "$1\n";
            print STDERR "$count\r";
            $count++;
        }
    }
}
