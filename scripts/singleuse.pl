#!/usr/bin/perl
#***************************************************************************
#                                  _   _ ____  _
#  Project                     ___| | | |  _ \| |
#                             / __| | | | |_) | |
#                            | (__| |_| |  _ <| |___
#                             \___|\___/|_| \_\_____|
#
# Copyright (C) 2019 - 2021, Daniel Stenberg, <daniel@haxx.se>, et al.
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
###########################################################################
#
# This script is aimed to help scan for and detect globally declared functions
# that are not used from other source files.
#
# Use it like this:
#
# $ ./scripts/singleuse.pl lib/.libs/libcurl.a
#
# Be aware that it might cause false positives due to various build options.
#

my $file = $ARGV[0];

my %wl = (
    'Curl_none_cert_status_request' => 'multiple TLS backends',
    'Curl_none_check_cxn' => 'multiple TLS backends',
    'Curl_none_cleanup' => 'multiple TLS backends',
    'Curl_none_close_all' => 'multiple TLS backends',
    'Curl_none_data_pending' => 'multiple TLS backends',
    'Curl_none_engines_list' => 'multiple TLS backends',
    'Curl_none_init' => 'multiple TLS backends',
    'Curl_none_md5sum' => 'multiple TLS backends',
    'Curl_none_random' => 'multiple TLS backends',
    'Curl_none_session_free' => 'multiple TLS backends',
    'Curl_none_set_engine' => 'multiple TLS backends',
    'Curl_none_set_engine_default' => 'multiple TLS backends',
    'Curl_none_shutdown' => 'multiple TLS backends',
    'Curl_multi_dump' => 'debug build only',
    'Curl_parse_port' => 'UNITTEST',
    'Curl_shuffle_addr' => 'UNITTEST',
    'de_cleanup' => 'UNITTEST',
    'doh_decode' => 'UNITTEST',
    'doh_encode' => 'UNITTEST',
    'Curl_auth_digest_get_pair' => 'by digest_sspi',
    'curlx_uztoso' => 'cmdline tool use',
    'curlx_uztoul' => 'by krb5_sspi',
    'curlx_uitous' => 'by schannel',
    'Curl_islower' => 'by curl_fnmatch',
    'getaddressinfo' => 'UNITTEST',
    );

my %api = (
    'curl_easy_cleanup' => 'API',
    'curl_easy_duphandle' => 'API',
    'curl_easy_escape' => 'API',
    'curl_easy_getinfo' => 'API',
    'curl_easy_init' => 'API',
    'curl_easy_pause' => 'API',
    'curl_easy_perform' => 'API',
    'curl_easy_recv' => 'API',
    'curl_easy_reset' => 'API',
    'curl_easy_send' => 'API',
    'curl_easy_setopt' => 'API',
    'curl_easy_strerror' => 'API',
    'curl_easy_unescape' => 'API',
    'curl_easy_upkeep' => 'API',
    'curl_easy_option_by_id' => 'API',
    'curl_easy_option_by_name' => 'API',
    'curl_easy_option_next' => 'API',
    'curl_escape' => 'API',
    'curl_formadd' => 'API',
    'curl_formfree' => 'API',
    'curl_formget' => 'API',
    'curl_free' => 'API',
    'curl_getdate' => 'API',
    'curl_getenv' => 'API',
    'curl_global_cleanup' => 'API',
    'curl_global_init' => 'API',
    'curl_global_init_mem' => 'API',
    'curl_global_sslset' => 'API',
    'curl_maprintf' => 'API',
    'curl_mfprintf' => 'API',
    'curl_mime_addpart' => 'API',
    'curl_mime_data' => 'API',
    'curl_mime_data_cb' => 'API',
    'curl_mime_encoder' => 'API',
    'curl_mime_filedata' => 'API',
    'curl_mime_filename' => 'API',
    'curl_mime_free' => 'API',
    'curl_mime_headers' => 'API',
    'curl_mime_init' => 'API',
    'curl_mime_name' => 'API',
    'curl_mime_subparts' => 'API',
    'curl_mime_type' => 'API',
    'curl_mprintf' => 'API',
    'curl_msnprintf' => 'API',
    'curl_msprintf' => 'API',
    'curl_multi_add_handle' => 'API',
    'curl_multi_assign' => 'API',
    'curl_multi_cleanup' => 'API',
    'curl_multi_fdset' => 'API',
    'curl_multi_info_read' => 'API',
    'curl_multi_init' => 'API',
    'curl_multi_perform' => 'API',
    'curl_multi_remove_handle' => 'API',
    'curl_multi_setopt' => 'API',
    'curl_multi_socket' => 'API',
    'curl_multi_socket_action' => 'API',
    'curl_multi_socket_all' => 'API',
    'curl_multi_poll' => 'API',
    'curl_multi_strerror' => 'API',
    'curl_multi_timeout' => 'API',
    'curl_multi_wait' => 'API',
    'curl_multi_wakeup' => 'API',
    'curl_mvaprintf' => 'API',
    'curl_mvfprintf' => 'API',
    'curl_mvprintf' => 'API',
    'curl_mvsnprintf' => 'API',
    'curl_mvsprintf' => 'API',
    'curl_pushheader_byname' => 'API',
    'curl_pushheader_bynum' => 'API',
    'curl_share_cleanup' => 'API',
    'curl_share_init' => 'API',
    'curl_share_setopt' => 'API',
    'curl_share_strerror' => 'API',
    'curl_slist_append' => 'API',
    'curl_slist_free_all' => 'API',
    'curl_strequal' => 'API',
    'curl_strnequal' => 'API',
    'curl_unescape' => 'API',
    'curl_url' => 'API',
    'curl_url_cleanup' => 'API',
    'curl_url_dup' => 'API',
    'curl_url_get' => 'API',
    'curl_url_set' => 'API',
    'curl_version' => 'API',
    'curl_version_info' => 'API',

    # the following functions are provided globally in debug builds
    'curl_easy_perform_ev' => 'debug-build',
    );

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
    if($l =~ /^([0-9a-f]+) T (.*)/) {
        my ($name)=($2);
        #print "Define $name in $file\n";
        $file =~ s/^libcurl_la-//;
        $exist{$name} = $file;
    }
    elsif($l =~ /^                 U (.*)/) {
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
        if($_ =~ /^curl_dbg_/) {
            # we ignore the memdebug symbols
        }
        elsif($_ =~ /^curl_/) {
            if(!$api{$_}) {
                # not present in the API, or for debug-builds
                print STDERR "Bad curl-prefix: $_\n";
                $err++;
            }
        }
        elsif($wl{$_}) {
            #print "$_ is WL\n";
        }
        else {
            printf "%s is defined in %s, but not used outside\n", $_, $exist{$_};
            $err++;
        }
    }
    elsif($_ =~ /^curl_/) {
        # global prefix, make sure it is "blessed"
        if(!$api{$_}) {
            # not present in the API, or for debug-builds
            if($_ !~ /^curl_dbg_/) {
                # ignore the memdebug symbols
                print STDERR "Bad curl-prefix $_\n";
                $err++;
            }
        }
    }
}

exit $err;
