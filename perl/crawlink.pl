#!/usr/bin/perl
#
# crawlink.pl
#
# This script crawls across all found links below the given "root" URL.
# It reports all good and bad links to stdout. This code was based on the
# checklink.pl script I wrote ages ago.
#
# Written to use 'curl' for URL checking.
#
# Author: Daniel Stenberg <daniel@haxx.se>
# Version: 0.3 Jan 3, 2001
#
# HISTORY
#
# 0.3 - The -i now adds regexes that if a full URL link matches one of those,
#       it is not followed. This can then be used to prevent this script from
#       following '.*\.cgi', specific pages or whatever.
#
# 0.2 - Made it only HEAD non html files (i.e skip the GET). Makes it a lot
#       faster to skip large non HTML files such as pdfs or big RFCs! ;-)
#       Added a -c option that allows me to pass options to curl.
#
# 0.1 - The given url works as the root. This script will only continue
#       and check other URLs if the leftmost part of the new URL is identical
#       to the root URL.
#

use strict;

my $in="";
my $verbose=0;
my $usestdin;
my $linenumber;
my $help;
my $external;
my $curlopts;

my @ignorelist;

 argv:
if($ARGV[0] eq "-v" ) {
    $verbose++;
    shift @ARGV;
    goto argv;
}
elsif($ARGV[0] eq "-c" ) {
    $curlopts=$ARGV[1];
    shift @ARGV;
    shift @ARGV;
    goto argv;
}
elsif($ARGV[0] eq "-i" ) {
    push @ignorelist, $ARGV[1];
    shift @ARGV;
    shift @ARGV;
    goto argv;
}
elsif($ARGV[0] eq "-l" ) {
    $linenumber = 1;
    shift @ARGV;
    goto argv;
}
elsif($ARGV[0] eq "-h" ) {
    $help = 1;
    shift @ARGV;
    goto argv;
}
elsif($ARGV[0] eq "-x" ) {
    $external = 1;
    shift @ARGV;
    goto argv;
}

my $geturl = $ARGV[0];
my $firsturl= $geturl;

#
# Define a hash array to hold all root URLs to visit/we have visited
#
my %rooturls;
$rooturls{$ARGV[0]}=1;

if(($geturl eq "") || $help) {
    print  "Usage: $0 [-hilvx] <full URL>\n",
    " Use a traling slash for directory URLs!\n",
    " -c [data]  Pass [data] as argument to every curl invoke\n",
    " -h         This help text\n",
    " -i [regex] Ignore root links that match this pattern\n",
    " -l         Line number report for BAD links\n",
    " -v         Verbose mode\n",
    " -x         Check non-local (external?) links only\n";
    exit;
}

my $proxy;
if($curlopts ne "") {
    $proxy=" $curlopts";
    #$proxy =" -x 194.237.142.41:80";
}

# linkchecker, URL will be appended to the right of this command line
# this is the one using HEAD:
my $linkcheck = "curl -s -m 20 -I$proxy";

# as a second attempt, this will be used. This is not using HEAD but will
# get the whole frigging document!
my $linkcheckfull = "curl -s -m 20 -i$proxy";

# htmlget, URL will be appended to the right of this command line
my $htmlget = "curl -s$proxy";

# Parse the input URL and split it into the relevant parts:

my $getprotocol;
my $getserver;
my $getpath;
my $getdocument;

my %done;
my %tagtype;
my $allcount=0;
my $badlinks=0;

sub SplitURL {
    my $inurl = $_[0];
    if($inurl=~ /^([^:]+):\/\/([^\/]*)\/(.*)\/(.*)/ ) {
	$getprotocol = $1;
	$getserver = $2;
	$getpath = $3;
	$getdocument = $4;
    }
    elsif ($inurl=~ /^([^:]+):\/\/([^\/]*)\/(.*)/ ) {
	$getprotocol = $1;
	$getserver = $2;
	$getpath = $3;
	$getdocument = "";
	
	if($getpath !~ /\//) {
	    $getpath ="";
	    $getdocument = $3;
	}
    
    }
    elsif ($inurl=~ /^([^:]+):\/\/(.*)/ ) {
	$getprotocol = $1;
	$getserver = $2;
	$getpath = "";
	$getdocument = "";
    }
    else {
	print "Couldn't parse the specified URL, retry please!\n";
	exit;
    }
}

my @indoc;

sub GetRootPage {
    my $geturl = $_[0];
    my $in="";
    my $code=200;
    my $type="text/plain";

    my $pagemoved=0;
    open(HEADGET, "$linkcheck $geturl|") ||
	die "Couldn't get web page for some reason";

    while(<HEADGET>) {
	#print STDERR $_;
	if($_ =~ /HTTP\/1\.[01] (\d\d\d) /) {
            $code=$1;
            if($code =~ /^3/) {
                $pagemoved=1;
            }
	}
        elsif($_ =~ /^Content-Type: ([\/a-zA-Z]+)/) {
            $type=$1;
        }
	elsif($pagemoved &&
	       ($_ =~ /^Location: (.*)/)) {
	    $geturl = $1;

	    &SplitURL($geturl);

	    $pagemoved++;
	    last;
	}
    }
    close(HEADGET);

    if($pagemoved == 1) {
	print "Page is moved but we don't know where. Did you forget the ",
	"traling slash?\n";
	exit;
    }

    if($type ne "text/html") {
        # there no point in getting anything but HTML
        $in="";
    }
    else {
        open(WEBGET, "$htmlget $geturl|") ||
            die "Couldn't get web page for some reason";
        while(<WEBGET>) {
            my $line = $_;
            push @indoc, $line;
            $line=~ s/\n/ /g;
            $line=~ s/\r//g;
            $in=$in.$line;
        }
        close(WEBGET);
    }
    return ($in, $code, $type);
}

sub LinkWorks {
    my $check = $_[0];

#   URL encode:
#    $check =~s/([^a-zA-Z0-9_:\/.-])/uc sprintf("%%%02x",ord($1))/eg;

    my @doc = `$linkcheck \"$check\"`;

    my $head = 1;

#    print "COMMAND: $linkcheck \"$check\"\n";
#    print $doc[0]."\n";

  boo:
    if( $doc[0] =~ /^HTTP[^ ]+ (\d+)/ ) {
	my $error = $1;

	if($error < 400 ) {
	    return "GOOD";
	}
	else {
	    
	    if($head && ($error >= 500)) {
		# This server doesn't like HEAD!
		@doc = `$linkcheckfull \"$check\"`;
		$head = 0;
		goto boo;
	    }
	    return "BAD";
	}
    }
    return "BAD";
}


sub GetLinks {
    my $in = $_[0];
    my @result;

    while($in =~ /[^<]*(<[^>]+>)/g ) {
	# we have a tag in $1
	my $tag = $1;
	
	if($tag =~ /^<!--/) {
	    # this is a comment tag, ignore it 
	}
	else {
	    if($tag =~ /(src|href|background|archive) *= *(\"[^\"]\"|[^ \)>]*)/i) {
   	        my $url=$2;
		if($url =~ /^\"(.*)\"$/) {
		    # this was a "string" now $1 has removed the quotes:
		    $url=$1;
		}


		$url =~ s/([^\#]*)\#.*/$1/g;

		if($url eq "") {
		    # if the link was nothing than a #-link it may now have
		    # been emptied completely so then we skip the rest
		    next;		    
		}

		if($done{$url}) {
		    # if this url already is done, do next
		    $done{$url}++;
                    if($verbose) {
                        print " FOUND $url but that is already checked\n";
                    }
		    next;
		}

		$done{$url} = 1; # this is "done"

	        push @result, $url;
		if($tag =~ /< *([^ ]+)/) {
		    $tagtype{$url}=$1;
		}
	    }
        }
    }
    return @result;
}


while(1) {
    $geturl=-1;
    for(keys %rooturls) {
        if($rooturls{$_} == 1) {
            if($_ !~ /^$firsturl/) {
                $rooturls{$_} += 1000; # don't do this, outside our scope
                if($verbose) {
                    print "SKIP: $_\n";
                }
                next;
            }
            $geturl=$_;
            last;
        }
    }
    if($geturl == -1) {
        last;
    }

    #
    # Splits the URL in its different parts
    #
    &SplitURL($geturl);

    #
    # Returns the full HTML of the root page
    #
    my ($in, $error, $ctype) = &GetRootPage($geturl);

    $rooturls{$geturl}++; # increase to prove we have already got it

    if($ctype ne "text/html") {
        # this is not HTML, we skip this
        if($verbose == 2) {
            print "Non-HTML link, skipping\n";
            next;
        }
    }

    if($error >= 400) {
        print "ROOT page $geturl returned $error\n";
        next;
    }

    print "    ==== $geturl ====\n";

    if($verbose == 2) {
        printf("Error code $error, Content-Type: $ctype, got %d bytes\n",
               length($in));
    }

    #print "protocol = $getprotocol\n";
    #print "server = $getserver\n";
    #print "path = $getpath\n";
    #print "document = $getdocument\n";
    #exit;
    
    #
    # Extracts all links from the given HTML buffer
    #
    my @links = &GetLinks($in);

    for(@links) {
        my $url = $_;
        my $link;

        if($url =~ /^([^:]+):/) {
            my $prot = $1;
            if($prot !~ /http/i) {
                # this is an unsupported protocol, we ignore this
                next;
            }
            $link = $url;
        }
        else {
            if($external) {
                next;
            }
            
            # this is a link on the same server:
            if($url =~ /^\//) {
                # from root
                $link = "$getprotocol://$getserver$url";
            }
            else {
                # from the scanned page's dir
                my $nyurl=$url;
                
                if(length($getpath) &&
                   ($getpath !~ /\/$/) &&
                   ($nyurl !~ /^\//)) {
                    # lacks ending slash, add one to the document part:
                    $nyurl = "/".$nyurl;
                }
                $link = "$getprotocol://$getserver/$getpath$nyurl";
            }
        }

        my $success = &LinkWorks($link);

        my $count = $done{$url};

        $allcount += $count;
        
        print "$success $count <".$tagtype{$url}."> $link $url\n";

        if("BAD" eq $success) {
            $badlinks++;
            if($linenumber) {
                my $line =1;
                for(@indoc) {
                    if($_ =~ /$url/) {
                        print " line $line\n";
                    }
                    $line++;
                }
            }
        }
        else {
            # the link works, add it if it isn't in the ingore list
            my $ignore=0;
            for(@ignorelist) {
                if($link =~ /$_/) {
                    $ignore=1;
                }
            }
            if(!$ignore) {
                # not ignored, add
                $rooturls{$link}++; # check this if not checked already
            }
        }
        
    }
}

if($verbose) {
    print "$allcount links were checked";
    if($badlinks > 0) {
	print ", $badlinks were found bad";
    }
    print "\n";
}
