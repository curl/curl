#!/usr/bin/env perl
#***************************************************************************
#                                  _   _ ____  _
#  Project                     ___| | | |  _ \| |
#                             / __| | | | |_) | |
#                            | (__| |_| |  _ <| |___
#                             \___|\___/|_| \_\_____|
#
# Copyright (C) 1998 - 2020, Daniel Stenberg, <daniel@haxx.se>, et al.
#
# This software is licensed as described in the file COPYING, which
# you should have received as part of this distribution. The terms
# are also available at https://curl.se/docs/copyright.html.
#
# You may opt to use, copy, modify, merge, publish, distribute and/or sell
# copies of the Software, and permit persons to whom the Software is
# furnished to do so, under the terms of the COPYING file.
#
# This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
# KIND, either express or implied.
#
#***************************************************************************

#=======================================================================
# Read a test definition which exercises curl's --libcurl option.
# Generate either compilable source code for a new test tool,
# or a new test definition which runs the tool and expects the
# same output.
# This should verify that the --libcurl code really does perform
# the same actions as the original curl invocation.
#-----------------------------------------------------------------------
# The output of curl's --libcurl option differs in several ways from
# the code needed to integrate with the test tool environment:
# - #include "test.h"
# - no call of curl_global_init & curl_global_cleanup
# - main() function vs. test() function
# - no checking of curl_easy_setopt calls vs. test_setopt wrapper
# - handling of stdout
# - variable names ret & hnd vs. res & curl
# - URL as literal string vs. passed as argument
#=======================================================================
use strict;
require "getpart.pm";

# Boilerplate code for test tool
my $head =
'#include "test.h"
#include "memdebug.h"

int test(char *URL)
{
  CURLcode res;
  CURL *curl;
';
# Other declarations from --libcurl come here
# e.g. curl_slist
my $init =
'
  if (curl_global_init(CURL_GLOBAL_ALL) != CURLE_OK) {
    fprintf(stderr, "curl_global_init() failed\n");
    return TEST_ERR_MAJOR_BAD;
  }

  if ((curl = curl_easy_init()) == NULL) {
    fprintf(stderr, "curl_easy_init() failed\n");
    curl_global_cleanup();
    return TEST_ERR_MAJOR_BAD;
  }
';
# Option setting, perform and cleanup come here
my $exit =
'  curl_global_cleanup();

  return (int)res;
}
';

my $myname = leaf($0);
sub usage {die "Usage: $myname -c|-test=num testfile\n";}

sub main {
    @ARGV == 2
        or usage;
    my($opt,$testfile) = @ARGV;

    if(loadtest($testfile)) {
        die "$myname: $testfile doesn't look like a test case\n";
    }

    my $comment = sprintf("DO NOT EDIT - generated from %s by %s",
                          leaf($testfile), $myname);
    if($opt eq '-c') {
        generate_c($comment);
    }
    elsif(my($num) = $opt =~ /^-test=(\d+)$/) {
        generate_test($comment, $num);
    }
    else {
        usage;
    }
}

sub generate_c {
    my($comment) = @_;
    # Fetch the generated code, which is the output file checked by
    # the old test.
    my @libcurl = getpart("verify", "file")
        or die "$myname: no <verify><file> section found\n";

    # Mangle the code into a suitable form for a test tool.
    # We want to extract the important parts (declarations,
    # URL, setopt calls, cleanup code) from the --libcurl
    # boilerplate and insert them into a new boilerplate.
    my(@decl,@code);
    # First URL passed in as argument, others as global
    my @urlvars = ('URL', 'libtest_arg2', 'libtest_arg3');
    my($seen_main,$seen_setopt,$seen_return);
    foreach (@libcurl) {
        # Check state changes first (even though it
        # duplicates some matches) so that the other tests
        # are in a logical order).
        if(/^int main/) {
            $seen_main = 1;
        }
        if($seen_main and /curl_easy_setopt/) {
            # Don't match 'curl_easy_setopt' in comment!
            $seen_setopt = 1;
        }
        if(/^\s*return/) {
            $seen_return = 1;
        }

        # Now filter the code according to purpose
        if(! $seen_main) {
            next;
        }
        elsif(! $seen_setopt) {
            if(/^\s*(int main|\{|CURLcode |CURL |hnd = curl_easy_init)/) {
                # Initialisations handled by boilerplate
                next;
            }
            else {
                push @decl, $_;
            }
        }
        elsif(! $seen_return) {
            if(/CURLOPT_URL/) {
                # URL is passed in as argument or by global
		my $var = shift @urlvars;
                s/\"[^\"]*\"/$var/;
            }
	    s/\bhnd\b/curl/;
            # Convert to macro wrapper
            s/curl_easy_setopt/test_setopt/;
	    if(/curl_easy_perform/) {
		s/\bret\b/res/;
		push @code, $_;
		push @code, "test_cleanup:\n";
	    }
	    else {
		push @code, $_;
	    }
        }
    }

    print ("/* $comment */\n",
           $head,
           @decl,
           $init,
           @code,
           $exit);
}

# Read the original test data file and transform it
# - add a "DO NOT EDIT comment"
# - replace CURLOPT_URL string with URL variable
# - remove <verify><file> section (was the --libcurl output)
# - insert a <client><tool> section with our new C program name
# - replace <client><command> section with the URL
sub generate_test {
    my($comment,$newnumber) = @_;
    my @libcurl = getpart("verify", "file")
        or die "$myname: no <verify><file> section found\n";
    # Scan the --libcurl code to find the URL used.
    my $url;
    foreach (@libcurl) {
        if(my($u) = /CURLOPT_URL, \"([^\"]*)\"/) {
            $url = $u;
        }
    }
    die "$myname: CURLOPT_URL not found\n"
        unless defined $url;

    # Traverse the pseudo-XML transforming as required
    my @new;
    my(@path,$path,$skip);
    foreach (getall()) {
        if(my($end) = /\s*<(\/?)testcase>/) {
            push @new, $_;
            push @new, "# $comment\n"
                unless $end;
        }
        elsif(my($tag) = /^\s*<(\w+)/) {
            push @path, $tag;
            $path = join '/', @path;
            if($path eq 'verify/file') {
                $skip = 1;
            }
            push @new, $_
                unless $skip;
            if($path eq 'client') {
                push @new, ("<tool>\n",
                            "lib$newnumber\n",
                            "</tool>\n");
            }
            elsif($path eq 'client/command') {
                push @new, sh_quote($url)."\n";
            }
        }
        elsif(my($etag) = /^\s*<\/(\w+)/) {
            my $tag = pop @path;
            die "$myname: mismatched </$etag>\n"
                unless $tag eq $etag;
            push @new, $_
                unless $skip;
            $skip --
                if $path eq 'verify/file';
            $path = join '/', @path;
        }
        else {
            if($path eq 'client/command') {
                # Replaced above
            }
            else {
                push @new, $_
                    unless $skip;
            }
        }
    }
    print @new;
}

sub leaf {
    # Works for POSIX filenames
    (my $path = shift) =~ s!.*/!!;
    return $path;
}

sub sh_quote {
    my $word = shift;
    $word =~ s/[\$\"\'\\]/\\$&/g;
    return '"' . $word . '"';
}

main;
