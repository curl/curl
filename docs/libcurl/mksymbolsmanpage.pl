#!/usr/bin/env perl
# ***************************************************************************
# *                                  _   _ ____  _
# *  Project                     ___| | | |  _ \| |
# *                             / __| | | | |_) | |
# *                            | (__| |_| |  _ <| |___
# *                             \___|\___/|_| \_\_____|
# *
# * Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
# *
# * This software is licensed as described in the file COPYING, which
# * you should have received as part of this distribution. The terms
# * are also available at https://curl.se/docs/copyright.html.
# *
# * You may opt to use, copy, modify, merge, publish, distribute and/or sell
# * copies of the Software, and permit persons to whom the Software is
# * furnished to do so, under the terms of the COPYING file.
# *
# * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
# * KIND, either express or implied.
# *
# * SPDX-License-Identifier: curl
# *
# ***************************************************************************

use POSIX qw(strftime);
my @ts;
if (defined($ENV{SOURCE_DATE_EPOCH})) {
    @ts = localtime($ENV{SOURCE_DATE_EPOCH});
} else {
    @ts = localtime;
}
my $date = strftime "%b %e, %Y", @ts;
my $year = strftime "%Y", @ts;

print <<HEADER
---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: libcurl-symbols
Section: 3
Source: libcurl
See-also:
  - libcurl (3)
  - libcurl-easy (3)
  - libcurl-multi (3)
  - libcurl-security (3)
  - libcurl-thread (3)
---
# libcurl symbols

This man page details version information for public symbols provided in the
libcurl header files. This lists the first version in which the symbol was
introduced and for some symbols two additional information pieces:

The first version in which the symbol is marked "deprecated" - meaning that
since that version no new code should be written to use the symbol as it is
marked for getting removed in a future.

The last version that featured the specific symbol. Using the symbol in source
code will make it no longer compile error-free after that specified version.

This man page is automatically generated from the symbols-in-versions file.
HEADER
    ;

sub nameref {
    my ($n)=@_;
    if($n =~ /^CURLOPT_/) {
        if($n eq "CURLOPT_RTSPHEADER") {
            $n = "CURLOPT_HTTPHEADER";
        }
        elsif($n eq "CURLOPT_WRITEHEADER") {
            $n = "CURLOPT_HEADERDATA";
        }
        elsif($n eq "CURLOPT_WRITEINFO") {
            ; # now obsolete
        }
        else {
            return "$n(3)";
        }
    }
    elsif($n =~ /^CURLMOPT_/) {
        return "$n(3)";
    }
    elsif($n =~ /^CURLINFO_/) {
        my %infotypes = (
            'CURLINFO_TEXT' => 1,
            'CURLINFO_HEADER_IN' => 1,
            'CURLINFO_HEADER_OUT' => 1,
            'CURLINFO_DATA_IN' => 1,
            'CURLINFO_DATA_OUT' => 1,
            'CURLINFO_SSL_DATA_IN' => 1,
            'CURLINFO_SSL_DATA_OUT' => 1,
            );
        if($infotypes{$n}) {
            return "CURLOPT_DEBUGFUNCTION(3)";
        }
    }
    elsif($n =~ /^CURLALTSVC_/) {
        return "CURLOPT_ALTSVC_CTRL(3)";
    }
    elsif($n =~ /^CURLAUTH_/) {
        return "CURLOPT_HTTPAUTH(3)";
    }
    elsif($n =~ /^CURLFORM_/) {
        return "curl_formadd(3)";
    }
    elsif($n =~ /^CURLKH/) {
        return "CURLOPT_SSH_KEYFUNCTION(3)";
    }
    elsif($n =~ /^CURLE_/) {
        return "libcurl-errors(3)";
    }
    elsif($n =~ /^CURLM_/) {
        return "libcurl-errors(3)";
    }
    elsif($n =~ /^CURLUE_/) {
        return "libcurl-errors(3)";
    }
    elsif($n =~ /^CURLHE_/) {
        return "libcurl-errors(3)";
    }
    elsif($n =~ /^CURLSHE_/) {
        return "libcurl-errors(3)";
    }
    elsif($n =~ /^CURLPROTO_/) {
        return "CURLINFO_PROTOCOL(3)";
    }
    elsif($n =~ /^CURLPX_/) {
        return "CURLINFO_PROXY_ERROR(3)";
    }
    elsif($n =~ /^CURLPROXY_/) {
        return "CURLOPT_PROXYTYPE(3)";
    }
    elsif($n =~ /^CURLSSLBACKEND_/) {
        return "curl_global_sslset(3)";
    }
    elsif($n =~ /^CURLSSLOPT_/) {
        return "CURLOPT_SSL_OPTIONS(3)";
    }
    elsif($n =~ /^CURLSSLSET_/) {
        return "curl_global_sslset(3)";
    }
    elsif($n =~ /^CURLUPART_/) {
        return "curl_url_get(3)";
    }
    elsif($n =~ /^CURLU_/) {
        return "curl_url_get(3)";
    }
    elsif($n =~ /^CURLVERSION_/) {
        return "curl_version_info(3)";
    }
    elsif($n =~ /^CURLSHOPT_/) {
        if($n eq "CURLSHOPT_NONE") {
            $n = "curl_share_setopt";
        }
        return "$n(3)";
    }
    elsif($n =~ /^CURLWS_/) {
        return "curl_ws_send(3)";
    }
    elsif($n =~ /^CURL_FORMADD_/) {
        return "curl_formadd(3)";
    }
    elsif($n =~ /^CURL_HTTPPOST_/) {
        return "curl_formadd(3)";
    }
    elsif($n =~ /^CURL_GLOBAL_/) {
        return "curl_global_init(3)";
    }
    elsif($n =~ /^CURL_HTTP_VERSION_/) {
        return "CURLOPT_HTTP_VERSION(3)";
    }
    elsif($n =~ /^CURL_LOCK_/) {
        return "CURLSHOPT_SHARE(3)";
    }
    elsif($n =~ /^CURL_SSLVERSION_/) {
        return "CURLOPT_SSLVERSION(3)";
    }
    elsif($n =~ /^CURL_VERSION_/) {
        return "curl_version_info(3)";
    }
    elsif($n =~ /^CURL_RTSPREQ_/) {
        return "CURLOPT_RTSP_REQUEST(3)";
    }
    elsif($n =~ /^CURLH_/) {
        return "curl_easy_header(3)";
    }
    elsif($n =~ /^CURL_TRAILERFUNC_/) {
        return "CURLOPT_TRAILERFUNCTION(3)";
    }
    elsif($n =~ /^CURLOT_/) {
        return "curl_easy_option_next(3)";
    }
    elsif($n =~ /^CURLFINFOFLAG_/) {
        return "CURLOPT_CHUNK_BGN_FUNCTION(3)";
    }
    elsif($n =~ /^CURLFILETYPE_/) {
        return "CURLOPT_CHUNK_BGN_FUNCTION(3)";
    }
    elsif($n =~ /^CURL_CHUNK_BGN_FUNC_/) {
        return "CURLOPT_CHUNK_BGN_FUNCTION(3)";
    }
    elsif($n =~ /^CURL_CHUNK_END_FUNC_/) {
        return "CURLOPT_CHUNK_END_FUNCTION(3)";
    }
    elsif($n =~ /^CURLSSH_AUTH_/) {
        return "CURLOPT_SSH_AUTH_TYPES(3)";
    }
    elsif($n =~ /^CURL_POLL_/) {
        return "CURLMOPT_SOCKETFUNCTION(3)";
    }
    elsif($n =~ /^CURLMSG_/) {
        return "curl_multi_info_read(3)";
    }
    elsif($n =~ /^CURLFTPAUTH_/) {
        return "CURLOPT_FTPSSLAUTH(3)";
    }
    elsif($n =~ /^CURLFTPMETHOD_/) {
        return "CURLOPT_FTP_FILEMETHOD(3)";
    }
    elsif($n =~ /^CURLFTPSSL_/) {
        return "CURLOPT_USE_SSL(3)";
    }
    elsif($n =~ /^CURLFTP_CREATE_/) {
        return "CURLOPT_FTP_CREATE_MISSING_DIRS(3)";
    }
    elsif($n =~ /^CURLGSSAPI_DELEGATION_/) {
        return "CURLOPT_GSSAPI_DELEGATION(3)";
    }
    elsif($n =~ /^CURLHEADER_/) {
        return "CURLOPT_HEADEROPT(3)";
    }
    elsif($n =~ /^CURLHSTS_/) {
        return "CURLOPT_HSTS_CTRL(3)";
    }
    elsif($n =~ /^CURLIOCMD_/) {
        return "CURLOPT_IOCTLFUNCTION(3)";
    }
    elsif($n =~ /^CURLIOE_/) {
        return "CURLOPT_IOCTLFUNCTION(3)";
    }
    elsif($n =~ /^CURLMIMEOPT_/) {
        return "CURLOPT_MIME_OPTIONS(3)";
    }
    elsif($n =~ /^CURLPAUSE_/) {
        return "curl_easy_pause(3)";
    }
    elsif($n =~ /^CURLPIPE_/) {
        return "CURLMOPT_PIPELINING(3)";
    }
    elsif($n =~ /^CURLSOCKTYPE_/) {
        return "CURLOPT_SOCKOPTFUNCTION(3)";
    }
    elsif($n =~ /^CURLSTS_/) {
        return "CURLOPT_HSTSREADFUNCTION(3)";
    }
    elsif($n =~ /^CURLUSESSL_/) {
        return "CURLOPT_USE_SSL(3)";
    }
    elsif($n =~ /^CURL_CSELECT_/) {
        return "curl_multi_socket_action(3)";
    }
    elsif($n =~ /^CURL_FNMATCHFUNC_/) {
        return "CURLOPT_FNMATCH_FUNCTION(3)";
    }
    elsif($n =~ /^CURL_HET_/) {
        return "CURLOPT_HAPPY_EYEBALLS_TIMEOUT_MS(3)";
    }
    elsif($n =~ /^CURL_IPRESOLVE_/) {
        return "CURLOPT_IPRESOLVE(3)";
    }
    elsif($n =~ /^CURL_SEEKFUNC_/) {
        return "CURLOPT_SEEKFUNCTION(3)";
    }
    elsif($n =~ /^CURL_TIMECOND_/) {
        return "CURLOPT_TIMECONDITION(3)";
    }
    elsif($n =~ /^CURL_REDIR_POST_/) {
        return "CURLOPT_POSTREDIR(3)";
    }
}

while(<STDIN>) {
    if($_ =~ /^(CURL[A-Z0-9_.]*) *(.*)/i) {
        my ($symbol, $rest)=($1,$2);
        my ($intro, $dep, $rem);
        if($rest =~ s/^([0-9.]*) *//) {
           $intro = $1;
        }
        if($rest =~ s/^([0-9.]*) *//) {
           $dep = $1;
        }
        if($rest =~ s/^- *([0-9.]*)//) {
           $rem = $1;
        }
        print "\n## $symbol\nIntroduced in $intro.";
        if($dep) {
            print " Deprecated since $dep.";
        }
        if($rem) {
            print " Last used in $rem.";
        }
        my $see = $rem || $dep ? "" : nameref($symbol);
        if($see) {
            print " See $see.";
        }
        print "\n";
    }
}
