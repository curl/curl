#!/usr/bin/perl
# Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
#
# SPDX-License-Identifier: curl
#
# Given: a libcurl curldown man page
# Outputs: the same file, minus the SYNOPSIS and the EXAMPLE sections
#

my $f = $ARGV[0];

open(F, "<$f") or die;

my @out;
my $ignore = 0;
while(<F>) {
    if($_ =~ /^# (SYNOPSIS|EXAMPLE)/) {
        $ignore = 1;
    }
    elsif($ignore && ($_ =~ /^# [A-Z]/)) {
        $ignore = 0;
    }
    elsif(!$ignore) {
        # **bold**
        $_ =~ s/\*\*(\S.*?)\*\*//g;
        # *italics*
        $_ =~ s/\*(\S.*?)\*//g;

        $_ =~ s/CURL(M|SH|U|H)code//g;
        $_ =~ s/CURL_[A-Z0-9_]*//g;
        $_ =~ s/CURLALTSVC_[A-Z0-9_]*//g;
        $_ =~ s/CURLAUTH_[A-Z0-9_]*//g;
        $_ =~ s/CURLE_[A-Z0-9_]*//g;
        $_ =~ s/CURLFORM_[A-Z0-9_]*//g;
        $_ =~ s/CURLFTP_[A-Z0-9_]*//g;
        $_ =~ s/CURLFTPAUTH_[A-Z0-9_]*//g;
        $_ =~ s/CURLFTPMETHOD_[A-Z0-9_]*//g;
        $_ =~ s/CURLFTPSSL_[A-Z0-9_]*//g;
        $_ =~ s/CURLGSSAPI_[A-Z0-9_]*//g;
        $_ =~ s/CURLHEADER_[A-Z0-9_]*//g;
        $_ =~ s/CURLINFO_[A-Z0-9_]*//g;
        $_ =~ s/CURLM_[A-Z0-9_]*//g;
        $_ =~ s/CURLMIMEOPT_[A-Z0-9_]*//g;
        $_ =~ s/CURLMOPT_[A-Z0-9_]*//g;
        $_ =~ s/CURLOPT_[A-Z0-9_]*//g;
        $_ =~ s/CURLPIPE_[A-Z0-9_]*//g;
        $_ =~ s/CURLPROTO_[A-Z0-9_]*//g;
        $_ =~ s/CURLPROXY_[A-Z0-9_]*//g;
        $_ =~ s/CURLPX_[A-Z0-9_]*//g;
        $_ =~ s/CURLSHE_[A-Z0-9_]*//g;
        $_ =~ s/CURLSHOPT_[A-Z0-9_]*//g;
        $_ =~ s/CURLSSLOPT_[A-Z0-9_]*//g;
        $_ =~ s/CURLSSH_[A-Z0-9_]*//g;
        $_ =~ s/CURLSSLBACKEND_[A-Z0-9_]*//g;
        $_ =~ s/CURLU_[A-Z0-9_]*//g;
        $_ =~ s/CURLUPART_[A-Z0-9_]*//g;
        #$_ =~ s/\bCURLU\b//g; # stand-alone CURLU
        $_ =~ s/CURLUE_[A-Z0-9_]*//g;
        $_ =~ s/CURLHE_[A-Z0-9_]*//g;
        $_ =~ s/CURLWS_[A-Z0-9_]*//g;
        $_ =~ s/CURLKH[A-Z0-9_]*//g;
        $_ =~ s/CURLUPART_[A-Z0-9_]*//g;
        $_ =~ s/CURLUSESSL_[A-Z0-9_]*//g;
        $_ =~ s/CURLPAUSE_[A-Z0-9_]*//g;
        $_ =~ s/CURLHSTS_[A-Z0-9_]*//g;
        $_ =~ s/curl_global_([a-z_]*)//g;
        $_ =~ s/curl_(strequal|strnequal|formadd|waitfd|formget|getdate|formfree)//g;
        $_ =~ s/curl_easy_([a-z]*)//g;
        $_ =~ s/curl_multi_([a-z_]*)//g;
        $_ =~ s/curl_mime_(subparts|addpart|filedata|data_cb)//g;
        $_ =~ s/curl_ws_(send|recv|meta)//g;
        $_ =~ s/curl_url_(dup)//g;
        $_ =~ s/curl_pushheader_by(name|num)//g;
        $_ =~ s/libcurl-(env|ws)//g;
        $_ =~ s/libcurl\\-(env|ws)//g;
        $_ =~ s/(^|\W)((tftp|https|http|ftp):\/\/[a-z0-9\-._~%:\/?\#\[\]\@!\$&'()*+,;=\\]+)//gi;
        push @out, $_;
    }
}
close(F);

open(O, ">$f") or die;
for my $l (@out) {
    print O $l;
}
close(O);
