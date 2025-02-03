#!/usr/bin/env perl
#***************************************************************************
#  Project
#                         _____       __         .__     
#                       _/ ____\_____/  |_  ____ |  |__  
#                       \   __\/ __ \   __\/ ___\|  |  \ 
#                       |  | \  ___/|  | \  \___|   Y  \
#                       |__|  \___  >__|  \___  >___|  /
#                                 \/          \/     \/
#
# Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
#
# This software is licensed as described in the file COPYING, which
# you should have received as part of this distribution. The terms
# are also available at https://fetch.se/docs/copyright.html.
#
# You may opt to use, copy, modify, merge, publish, distribute and/or sell
# copies of the Software, and permit persons to whom the Software is
# furnished to do so, under the terms of the COPYING file.
#
# This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
# KIND, either express or implied.
#
# SPDX-License-Identifier: fetch
#
###########################################################################
#
# This script is aimed to help scan for and detect globally declared functions
# that are not used from other source files.
#
# Use it like this:
#
# $ ./scripts/singleuse.pl [--unit] lib/.libs/libfetch.a
#
# --unit : built to support unit tests
#

my $unittests;
if($ARGV[0] eq "--unit") {
    $unittests = "tests/unit ";
    shift @ARGV;
}

my $file = $ARGV[0];

my %wl = (
    'Curl_xfer_write_resp' => 'internal api',
    'Curl_creader_def_init' => 'internal api',
    'Curl_creader_def_close' => 'internal api',
    'Curl_creader_def_read' => 'internal api',
    'Curl_creader_def_total_length' => 'internal api',
);

my %api = (
    'fetch_easy_cleanup' => 'API',
    'fetch_easy_duphandle' => 'API',
    'fetch_easy_escape' => 'API',
    'fetch_easy_getinfo' => 'API',
    'fetch_easy_init' => 'API',
    'fetch_easy_pause' => 'API',
    'fetch_easy_perform' => 'API',
    'fetch_easy_recv' => 'API',
    'fetch_easy_reset' => 'API',
    'fetch_easy_send' => 'API',
    'fetch_easy_setopt' => 'API',
    'fetch_easy_ssls_export' => 'API',
    'fetch_easy_ssls_import' => 'API',
    'fetch_easy_strerror' => 'API',
    'fetch_easy_unescape' => 'API',
    'fetch_easy_upkeep' => 'API',
    'fetch_easy_option_by_id' => 'API',
    'fetch_easy_option_by_name' => 'API',
    'fetch_easy_option_next' => 'API',
    'fetch_escape' => 'API',
    'fetch_formadd' => 'API',
    'fetch_formfree' => 'API',
    'fetch_formget' => 'API',
    'fetch_free' => 'API',
    'fetch_getdate' => 'API',
    'fetch_getenv' => 'API',
    'fetch_global_cleanup' => 'API',
    'fetch_global_init' => 'API',
    'fetch_global_init_mem' => 'API',
    'fetch_global_sslset' => 'API',
    'fetch_global_trace' => 'API',
    'fetch_maprintf' => 'API',
    'fetch_mfprintf' => 'API',
    'fetch_mime_addpart' => 'API',
    'fetch_mime_data' => 'API',
    'fetch_mime_data_cb' => 'API',
    'fetch_mime_encoder' => 'API',
    'fetch_mime_filedata' => 'API',
    'fetch_mime_filename' => 'API',
    'fetch_mime_free' => 'API',
    'fetch_mime_headers' => 'API',
    'fetch_mime_init' => 'API',
    'fetch_mime_name' => 'API',
    'fetch_mime_subparts' => 'API',
    'fetch_mime_type' => 'API',
    'fetch_mprintf' => 'API',
    'fetch_msnprintf' => 'API',
    'fetch_msprintf' => 'API',
    'fetch_multi_add_handle' => 'API',
    'fetch_multi_assign' => 'API',
    'fetch_multi_cleanup' => 'API',
    'fetch_multi_fdset' => 'API',
    'fetch_multi_get_handles' => 'API',
    'fetch_multi_info_read' => 'API',
    'fetch_multi_init' => 'API',
    'fetch_multi_perform' => 'API',
    'fetch_multi_remove_handle' => 'API',
    'fetch_multi_setopt' => 'API',
    'fetch_multi_socket' => 'API',
    'fetch_multi_socket_action' => 'API',
    'fetch_multi_socket_all' => 'API',
    'fetch_multi_poll' => 'API',
    'fetch_multi_strerror' => 'API',
    'fetch_multi_timeout' => 'API',
    'fetch_multi_wait' => 'API',
    'fetch_multi_waitfds' => 'API',
    'fetch_multi_wakeup' => 'API',
    'fetch_mvaprintf' => 'API',
    'fetch_mvfprintf' => 'API',
    'fetch_mvprintf' => 'API',
    'fetch_mvsnprintf' => 'API',
    'fetch_mvsprintf' => 'API',
    'fetch_pushheader_byname' => 'API',
    'fetch_pushheader_bynum' => 'API',
    'fetch_share_cleanup' => 'API',
    'fetch_share_init' => 'API',
    'fetch_share_setopt' => 'API',
    'fetch_share_strerror' => 'API',
    'fetch_slist_append' => 'API',
    'fetch_slist_free_all' => 'API',
    'fetch_strequal' => 'API',
    'fetch_strnequal' => 'API',
    'fetch_unescape' => 'API',
    'fetch_url' => 'API',
    'fetch_url_cleanup' => 'API',
    'fetch_url_dup' => 'API',
    'fetch_url_get' => 'API',
    'fetch_url_set' => 'API',
    'fetch_url_strerror' => 'API',
    'fetch_version' => 'API',
    'fetch_version_info' => 'API',
    'fetch_easy_header' => 'API',
    'fetch_easy_nextheader' => 'API',
    'fetch_ws_meta' => 'API',
    'fetch_ws_recv' => 'API',
    'fetch_ws_send' => 'API',

    # the following functions are provided globally in debug builds
    'fetch_easy_perform_ev' => 'debug-build',
    );

sub doublecheck {
    my ($f, $used) = @_;
    open(F, "git grep -Fwle '$f' -- lib ${unittests}packages|");
    my @also;
    while(<F>) {
        my $e = $_;
        chomp $e;
        if($e =~ /\.[c]$/) {
            if($e !~ /^lib\/${used}\.c/) {
                push @also, $e;
            }
        }
    }
    close(F);
    return @also;
}

open(N, "nm $file|") ||
    die;

my %exist;
my %uses;
my $file;
while (<N>) {
    my $l = $_;
    chomp $l;

    if($l =~ /^([0-9a-z_-]+)\.o:/) {
        $file = $1;
    }
    # libfetch.a(unity_0_c.c.o):
    elsif($l =~ /\(([0-9a-z_.-]+)\.o\):/) {  # Apple nm
        $file = $1;
    }
    if($l =~ /^([0-9a-f]+) T _?(.*)/) {
        my ($name)=($2);
        #print "Define $name in $file\n";
        $file =~ s/^libfetch_la-//;
        $exist{$name} = $file;
    }
    elsif($l =~ /^                 U _?(.*)/) {
        my ($name)=($1);
        #print "Uses $name in $file\n";
        $uses{$name} .= "$file, ";
    }
}
close(N);

my $err;
for(sort keys %exist) {
    #printf "%s is defined in %s, used by: %s\n", $_, $exist{$_}, $uses{$_};
    if(!$uses{$_}) {
        # this is a symbol with no "global" user
        if($_ =~ /^fetch_dbg_/) {
            # we ignore the memdebug symbols
        }
        elsif($_ =~ /^fetch_/) {
            if(!$api{$_}) {
                # not present in the API, or for debug-builds
                print STDERR "Bad fetch-prefix: $_\n";
                $err++;
            }
        }
        elsif($wl{$_}) {
            #print "$_ is WL\n";
        }
        else {
            my $c = $_;
            my @also = doublecheck($c, $exist{$c});
            if(!scalar(@also)) {
                printf "%s in %s\n", $c, $exist{$c};
                $err++;
            }
            #    foreach my $a (@also) {
            #        print "  $a\n";
            #    }
        }
    }
    elsif($_ =~ /^fetch_/) {
        # global prefix, make sure it is "blessed"
        if(!$api{$_}) {
            # not present in the API, or for debug-builds
            if($_ !~ /^fetch_dbg_/) {
                # ignore the memdebug symbols
                print STDERR "Bad fetch-prefix $_\n";
                $err++;
            }
        }
    }
}

exit $err;
