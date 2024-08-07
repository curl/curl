#***************************************************************************
#                                  _   _ ____  _
#  Project                     ___| | | |  _ \| |
#                             / __| | | | |_) | |
#                            | (__| |_| |  _ <| |___
#                             \___|\___/|_| \_\_____|
#
# Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
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
# SPDX-License-Identifier: curl
#
###########################################################################

# This module contains miscellaneous functions needed in several parts of
# the test suite.

package testutil;

use strict;
use warnings;

BEGIN {
    use base qw(Exporter);

    our @EXPORT = qw(
        runclient
        runclientoutput
        setlogfunc
        shell_quote
        subbase64
        subnewlines
        subsha256base64file
        substrippemfile
    );

    our @EXPORT_OK = qw(
        clearlogs
        logmsg
    );
}

use Digest::SHA qw(sha256);
use MIME::Base64;

use globalconfig qw(
    $torture
    $verbose
);

my $logfunc;      # optional reference to function for logging
my @logmessages;  # array holding logged messages


#######################################################################
# Log an informational message
# If a log callback function was set in setlogfunc, it is called. If not,
# then the log message is buffered until retrieved by clearlogs.
#
# logmsg must only be called by one of the runner_* entry points and functions
# called by them, or else logs risk being lost, since those are the only
# functions that know about and will return buffered logs.
sub logmsg {
    if(!scalar(@_)) {
        return;
    }
    if(defined $logfunc) {
        &$logfunc(@_);
        return;
    }
    push @logmessages, @_;
}

#######################################################################
# Set the function to use for logging
sub setlogfunc {
    ($logfunc)=@_;
}

#######################################################################
# Clear the buffered log messages after returning them
sub clearlogs {
    my $loglines = join('', @logmessages);
    undef @logmessages;
    return $loglines;
}


#######################################################################

sub includefile {
    my ($f) = @_;
    open(F, "<$f");
    my @a = <F>;
    close(F);
    return join("", @a);
}

sub subbase64 {
    my ($thing) = @_;

    # cut out the base64 piece
    while($$thing =~ s/%b64\[(.*?)\]b64%/%%B64%%/i) {
        my $d = $1;
        # encode %NN characters
        $d =~ s/%([0-9A-Fa-f]{2})/chr(hex($1))/eg;
        my $enc = encode_base64($d, "");
        # put the result into there
        $$thing =~ s/%%B64%%/$enc/;
    }
    # hex decode
    while($$thing =~ s/%hex\[(.*?)\]hex%/%%HEX%%/i) {
        # decode %NN characters
        my $d = $1;
        $d =~ s/%([0-9A-Fa-f]{2})/chr(hex($1))/eg;
        $$thing =~ s/%%HEX%%/$d/;
    }
    # repeat
    while($$thing =~ s/%repeat\[(\d+) x (.*?)\]%/%%REPEAT%%/i) {
        # decode %NN characters
        my ($d, $n) = ($2, $1);
        $d =~ s/%([0-9A-Fa-f]{2})/chr(hex($1))/eg;
        $n =~ s/%([0-9A-Fa-f]{2})/chr(hex($1))/eg;
        my $all = $d x $n;
        $$thing =~ s/%%REPEAT%%/$all/;
    }

    # include a file
    $$thing =~ s/%include ([^%]*)%[\n\r]+/includefile($1)/ge;
}

my $prevupdate;  # module scope so it remembers the last value
sub subnewlines {
    my ($force, $thing) = @_;

    if($force) {
        # enforce CRLF newline
        $$thing =~ s/\x0d*\x0a/\x0d\x0a/;
        return;
    }

    # When curl is built with Hyper, it gets all response headers delivered as
    # name/value pairs and curl "invents" the newlines when it saves the
    # headers. Therefore, curl will always save headers with CRLF newlines
    # when built to use Hyper. By making sure we deliver all tests using CRLF
    # as well, all test comparisons will survive without knowing about this
    # little quirk.

    if(($$thing =~ /^HTTP\/(1.1|1.0|2|3) [1-5][^\x0d]*\z/) ||
       ($$thing =~ /^(GET|POST|PUT|DELETE) \S+ HTTP\/\d+(\.\d+)?/) ||
       (($$thing =~ /^[a-z0-9_-]+: [^\x0d]*\z/i) &&
        # skip curl error messages
        ($$thing !~ /^curl: \(\d+\) /))) {
        # enforce CRLF newline
        $$thing =~ s/\x0d*\x0a/\x0d\x0a/;
        $prevupdate = 1;
    }
    else {
        if(($$thing =~ /^\n\z/) && $prevupdate) {
            # if there's a blank link after a line we update, we hope it is
            # the empty line following headers
            $$thing =~ s/\x0a/\x0d\x0a/;
        }
        $prevupdate = 0;
    }
}

#######################################################################
# Run the application under test and return its return code
#
sub runclient {
    my ($cmd)=@_;
    my $ret = system($cmd);
    print "CMD ($ret): $cmd\n" if($verbose && !$torture);
    return $ret;

# This is one way to test curl on a remote machine
#    my $out = system("ssh $CLIENTIP cd \'$pwd\' \\; \'$cmd\'");
#    sleep 2;    # time to allow the NFS server to be updated
#    return $out;
}

#######################################################################
# Run the application under test and return its stdout
#
sub runclientoutput {
    my ($cmd)=@_;
    return `$cmd 2>/dev/null`;

# This is one way to test curl on a remote machine
#    my @out = `ssh $CLIENTIP cd \'$pwd\' \\; \'$cmd\'`;
#    sleep 2;    # time to allow the NFS server to be updated
#    return @out;
}


#######################################################################
# Quote an argument for passing safely to a Bourne shell
# This does the same thing as String::ShellQuote but doesn't need a package.
#
sub shell_quote {
    my ($s)=@_;
    if($s !~ m/^[-+=.,_\/:a-zA-Z0-9]+$/) {
        # string contains a "dangerous" character--quote it
        $s =~ s/'/'"'"'/g;
        $s = "'" . $s . "'";
    }
    return $s;
}

sub get_sha256_base64 {
    my ($file_path) = @_;
    return encode_base64(sha256(do { local $/; open my $fh, '<:raw', $file_path or die $!; <$fh> }), "");
}

sub subsha256base64file {
    my ($thing) = @_;

    # SHA-256 base64
    while ($$thing =~ s/%sha256b64file\[(.*?)\]sha256b64file%/%%SHA256B64FILE%%/i) {
        my $file_path = $1;
        $file_path =~ s/%([0-9A-Fa-f]{2})/chr(hex($1))/eg;
        my $hash_b64 = get_sha256_base64($file_path);
        $$thing =~ s/%%SHA256B64FILE%%/$hash_b64/;
    }
}

sub get_file_content {
    my ($file_path) = @_;
    my $content = do { local $/; open my $fh, '<', $file_path or die $!; <$fh> };
    $content =~ s/(^|-----END .*?-----[\r\n]?)(.*?)(-----BEGIN .*?-----|$)/$1$3/gs;
    $content =~ s/\r\n/\n/g;
    chomp($content);
    return $content;
}

sub substrippemfile {
    my ($thing) = @_;

    # File content substitution
    while ($$thing =~ s/%strippemfile\[(.*?)\]strippemfile%/%%FILE%%/i) {
        my $file_path = $1;
        $file_path =~ s/%([0-9A-Fa-f]{2})/chr(hex($1))/eg;
        my $file_content = get_file_content($file_path);
        $$thing =~ s/%%FILE%%/$file_content/;
    }
}
1;
