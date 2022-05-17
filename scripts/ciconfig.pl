#!/usr/bin/perl
#***************************************************************************
#                                  _   _ ____  _
#  Project                     ___| | | |  _ \| |
#                             / __| | | | |_) | |
#                            | (__| |_| |  _ <| |___
#                             \___|\___/|_| \_\_____|
#
# Copyright (C) 2022, Daniel Stenberg, <daniel@haxx.se>, et al.
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

# these options are enabled by default in the sense that they will attempt to
# check for and use this feature without the configure flag
my %defaulton = (
    # --enable-
    'shared' => 1,
    'static' => 1,
    'fast-install' => 1,
    'silent-rules' => 1,
    'optimize' => 1,
    'http' => 1,
    'ftp' => 1,
    'file' => 1,
    'ldap' => 1,
    'ldaps' => 1,
    'rtsp' => 1,
    'proxy' => 1,
    'dict' => 1,
    'telnet' => 1,
    'tftp' => 1,
    'pop3' => 1,
    'imap' => 1,
    'smb' => 1,
    'smtp' => 1,
    'gopher' => 1,
    'mqtt' => 1,
    'manual' => 1,
    'libcurl-option' => 1,
    'libgcc' => 1,
    'ipv6' => 1,
    'openssl-auto-load-config' => 1,
    'versioned-symbols' => 1,
    'symbol-hiding' => 1,
    'threaded-resolver' => 1,
    'pthreads' => 1,
    'verbose' => 1,
    'crypto-auth' => 1,
    'ntlm' => 1,
    'ntlm-wb' => 1,
    'tls-srp' => 1,
    'unix-sockets' => 1,
    'cookies' => 1,
    'socketpair' => 1,
    'http-auth' => 1,
    'doh' => 1,
    'mime' => 1,
    'dateparse' => 1,
    'netrc' => 1,
    'progress-meter' => 1,
    'dnsshuffle' => 1,
    'get-easy-options' => 1,
    'alt-svc' => 1,
    'hsts' => 1,

    # --with-
    'aix-soname' => 1,
    'pic' => 1,
    'zlib' => 1,
    'zstd' => 1,
    'brotli' => 1,
    'random' => 1,
    'egd-socket' => 1,
    'ca-bundle' => 1,
    'ca-path' => 1,
    'libssh2' => 1,
    'nghttp2' => 1,
    'librtmp' => 1,
    'libidn2' => 1,
    'sysroot' => 1,
    'lber-lib' => 1,
    'ldap-lib' => 1,

    );


sub configureopts {
    my ($opts)=@_;
    my %thisin;
    my %thisout;

    while($opts =~ s/--with-([^ =]*)//) {
        $with{$1}++;
        $used{$1}++;
        $thisin{$1}++;
    }
    while($opts =~ s/--enable-([^ =]*)//) {
        $with{$1}++;
        $used{$1}++;
        $thisin{$1}++;
    }

    while($opts =~ s/--without-([^ =]*)//) {
        $without{$1}++;
        $used{$1}++;
        $thisout{$1}++;
    }
    while($opts =~ s/--disable-([^ =]*)//) {
        $without{$1}++;
        $used{$1}++;
        $thisout{$1}++;
    }
    return join(" ", sort(keys %thisin), "/", sort(keys %thisout));
}

# run configure --help and check what available WITH/ENABLE options that exist
sub configurehelp {
    open(C, "./configure --help|");
    while(<C>) {
        if($_ =~ /^  --(with|enable)-([a-z0-9-]+)/) {
            $avail{$2}++;
        }
    }
    close(C);
}

sub scanjobs {

    my $jobs;
    open(CI, "./scripts/cijobs.pl|");
    while(<CI>) {
        if($_ =~ /^\#\#\#/) {
            $jobs++;
        }
        if($_ =~ /^configure: (.*)/) {
            my $c= configureopts($1);
            #print "C: $c\n";
        }
    }
    close(CI);
}

configurehelp();
scanjobs();

print "Used configure options (with / without)\n";
for my $w (sort keys %used) {
    printf "  %s: %d %d%s\n", $w, $with{$w}, $without{$w},
        $defaulton{$w} ? " (auto)":"";
}

print "Never used configure options\n";
for my $w (sort keys %avail) {
    if(!$used{$w}) {
        printf "  %s%s\n", $w,
            $defaulton{$w} ? " (auto)":"";
    }
}

print "Never ENABLED configure options that aren't on by default\n";
for my $w (sort keys %avail) {
    if(!$with{$w} && !$defaulton{$w}) {
        printf "  %s\n", $w;
    }
}


print "ENABLED configure options that aren't available\n";
for my $w (sort keys %with) {
    if(!$avail{$w}) {
        printf "  %s\n", $w;
    }
}
