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
# * SPDX-License-Identifier: fetch
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
SPDX-License-Identifier: fetch
Title: libfetch-symbols
Section: 3
Source: libfetch
Protocol:
  - All
See-also:
  - libfetch (3)
  - libfetch-easy (3)
  - libfetch-multi (3)
  - libfetch-security (3)
  - libfetch-thread (3)
Added-in: n/a
---
# libfetch symbols

This man page details version information for public symbols provided in the
libfetch header files. This lists the first version in which the symbol was
introduced and for some symbols two additional information pieces:

The first version in which the symbol is marked "deprecated" - meaning that
since that version no new code should be written to use the symbol as it is
marked for getting removed in a future.

The last version that featured the specific symbol. Using the symbol in source
code makes it no longer compile error-free after that specified version.

This man page is automatically generated from the symbols-in-versions file.
HEADER
    ;

sub nameref {
    my ($n)=@_;
    if($n =~ /^FETCHOPT_/) {
        if($n eq "FETCHOPT_RTSPHEADER") {
            $n = "FETCHOPT_HTTPHEADER";
        }
        elsif($n eq "FETCHOPT_WRITEHEADER") {
            $n = "FETCHOPT_HEADERDATA";
        }
        elsif($n eq "FETCHOPT_WRITEINFO") {
            ; # now obsolete
        }
        else {
            return "$n(3)";
        }
    }
    elsif($n =~ /^FETCHMOPT_/) {
        return "$n(3)";
    }
    elsif($n =~ /^FETCHINFO_/) {
        my %infotypes = (
            'FETCHINFO_TEXT' => 1,
            'FETCHINFO_HEADER_IN' => 1,
            'FETCHINFO_HEADER_OUT' => 1,
            'FETCHINFO_DATA_IN' => 1,
            'FETCHINFO_DATA_OUT' => 1,
            'FETCHINFO_SSL_DATA_IN' => 1,
            'FETCHINFO_SSL_DATA_OUT' => 1,
            );
        if($infotypes{$n}) {
            return "FETCHOPT_DEBUGFUNCTION(3)";
        }
    }
    elsif($n =~ /^FETCHALTSVC_/) {
        return "FETCHOPT_ALTSVC_CTRL(3)";
    }
    elsif($n =~ /^FETCHAUTH_/) {
        return "FETCHOPT_HTTPAUTH(3)";
    }
    elsif($n =~ /^FETCHFORM_/) {
        return "fetch_formadd(3)";
    }
    elsif($n =~ /^FETCHKH/) {
        return "FETCHOPT_SSH_KEYFUNCTION(3)";
    }
    elsif($n =~ /^FETCHE_/) {
        return "libfetch-errors(3)";
    }
    elsif($n =~ /^FETCHM_/) {
        return "libfetch-errors(3)";
    }
    elsif($n =~ /^FETCHUE_/) {
        return "libfetch-errors(3)";
    }
    elsif($n =~ /^FETCHHE_/) {
        return "libfetch-errors(3)";
    }
    elsif($n =~ /^FETCHSHE_/) {
        return "libfetch-errors(3)";
    }
    elsif($n =~ /^FETCHPROTO_/) {
        return "FETCHINFO_PROTOCOL(3)";
    }
    elsif($n =~ /^FETCHPX_/) {
        return "FETCHINFO_PROXY_ERROR(3)";
    }
    elsif($n =~ /^FETCHPROXY_/) {
        return "FETCHOPT_PROXYTYPE(3)";
    }
    elsif($n =~ /^FETCHSSLBACKEND_/) {
        return "fetch_global_sslset(3)";
    }
    elsif($n =~ /^FETCHSSLOPT_/) {
        return "FETCHOPT_SSL_OPTIONS(3)";
    }
    elsif($n =~ /^FETCHSSLSET_/) {
        return "fetch_global_sslset(3)";
    }
    elsif($n =~ /^FETCHUPART_/) {
        return "fetch_url_get(3)";
    }
    elsif($n =~ /^FETCHU_/) {
        return "fetch_url_get(3)";
    }
    elsif($n =~ /^FETCHVERSION_/) {
        return "fetch_version_info(3)";
    }
    elsif($n =~ /^FETCHSHOPT_/) {
        if($n eq "FETCHSHOPT_NONE") {
            $n = "fetch_share_setopt";
        }
        return "$n(3)";
    }
    elsif($n =~ /^FETCHWS_/) {
        return "fetch_ws_send(3)";
    }
    elsif($n =~ /^FETCH_FORMADD_/) {
        return "fetch_formadd(3)";
    }
    elsif($n =~ /^FETCH_HTTPPOST_/) {
        return "fetch_formadd(3)";
    }
    elsif($n =~ /^FETCH_GLOBAL_/) {
        return "fetch_global_init(3)";
    }
    elsif($n =~ /^FETCH_HTTP_VERSION_/) {
        return "FETCHOPT_HTTP_VERSION(3)";
    }
    elsif($n =~ /^FETCH_LOCK_/) {
        return "FETCHSHOPT_SHARE(3)";
    }
    elsif($n =~ /^FETCH_SSLVERSION_/) {
        return "FETCHOPT_SSLVERSION(3)";
    }
    elsif($n =~ /^FETCH_VERSION_/) {
        return "fetch_version_info(3)";
    }
    elsif($n =~ /^FETCH_RTSPREQ_/) {
        return "FETCHOPT_RTSP_REQUEST(3)";
    }
    elsif($n =~ /^FETCHH_/) {
        return "fetch_easy_header(3)";
    }
    elsif($n =~ /^FETCH_TRAILERFUNC_/) {
        return "FETCHOPT_TRAILERFUNCTION(3)";
    }
    elsif($n =~ /^FETCHOT_/) {
        return "fetch_easy_option_next(3)";
    }
    elsif($n =~ /^FETCHFINFOFLAG_/) {
        return "FETCHOPT_CHUNK_BGN_FUNCTION(3)";
    }
    elsif($n =~ /^FETCHFILETYPE_/) {
        return "FETCHOPT_CHUNK_BGN_FUNCTION(3)";
    }
    elsif($n =~ /^FETCH_CHUNK_BGN_FUNC_/) {
        return "FETCHOPT_CHUNK_BGN_FUNCTION(3)";
    }
    elsif($n =~ /^FETCH_CHUNK_END_FUNC_/) {
        return "FETCHOPT_CHUNK_END_FUNCTION(3)";
    }
    elsif($n =~ /^FETCHSSH_AUTH_/) {
        return "FETCHOPT_SSH_AUTH_TYPES(3)";
    }
    elsif($n =~ /^FETCH_POLL_/) {
        return "FETCHMOPT_SOCKETFUNCTION(3)";
    }
    elsif($n =~ /^FETCHMSG_/) {
        return "fetch_multi_info_read(3)";
    }
    elsif($n =~ /^FETCHFTPAUTH_/) {
        return "FETCHOPT_FTPSSLAUTH(3)";
    }
    elsif($n =~ /^FETCHFTPMETHOD_/) {
        return "FETCHOPT_FTP_FILEMETHOD(3)";
    }
    elsif($n =~ /^FETCHFTPSSL_/) {
        return "FETCHOPT_USE_SSL(3)";
    }
    elsif($n =~ /^FETCHFTP_CREATE_/) {
        return "FETCHOPT_FTP_CREATE_MISSING_DIRS(3)";
    }
    elsif($n =~ /^FETCHGSSAPI_DELEGATION_/) {
        return "FETCHOPT_GSSAPI_DELEGATION(3)";
    }
    elsif($n =~ /^FETCHHEADER_/) {
        return "FETCHOPT_HEADEROPT(3)";
    }
    elsif($n =~ /^FETCHHSTS_/) {
        return "FETCHOPT_HSTS_CTRL(3)";
    }
    elsif($n =~ /^FETCHIOCMD_/) {
        return "FETCHOPT_IOCTLFUNCTION(3)";
    }
    elsif($n =~ /^FETCHIOE_/) {
        return "FETCHOPT_IOCTLFUNCTION(3)";
    }
    elsif($n =~ /^FETCHMIMEOPT_/) {
        return "FETCHOPT_MIME_OPTIONS(3)";
    }
    elsif($n =~ /^FETCHPAUSE_/) {
        return "fetch_easy_pause(3)";
    }
    elsif($n =~ /^FETCHPIPE_/) {
        return "FETCHMOPT_PIPELINING(3)";
    }
    elsif($n =~ /^FETCHSOCKTYPE_/) {
        return "FETCHOPT_SOCKOPTFUNCTION(3)";
    }
    elsif($n =~ /^FETCHSTS_/) {
        return "FETCHOPT_HSTSREADFUNCTION(3)";
    }
    elsif($n =~ /^FETCHUSESSL_/) {
        return "FETCHOPT_USE_SSL(3)";
    }
    elsif($n =~ /^FETCH_CSELECT_/) {
        return "fetch_multi_socket_action(3)";
    }
    elsif($n =~ /^FETCH_FNMATCHFUNC_/) {
        return "FETCHOPT_FNMATCH_FUNCTION(3)";
    }
    elsif($n =~ /^FETCH_HET_/) {
        return "FETCHOPT_HAPPY_EYEBALLS_TIMEOUT_MS(3)";
    }
    elsif($n =~ /^FETCH_IPRESOLVE_/) {
        return "FETCHOPT_IPRESOLVE(3)";
    }
    elsif($n =~ /^FETCH_SEEKFUNC_/) {
        return "FETCHOPT_SEEKFUNCTION(3)";
    }
    elsif($n =~ /^FETCH_TIMECOND_/) {
        return "FETCHOPT_TIMECONDITION(3)";
    }
    elsif($n =~ /^FETCH_REDIR_POST_/) {
        return "FETCHOPT_POSTREDIR(3)";
    }
}

while(<STDIN>) {
    if($_ =~ /^(FETCH[A-Z0-9_.]*) *(.*)/i) {
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
