#!/usr/bin/env perl
#***************************************************************************
#                                  _   _ ____  _
#  Project                     ___| | | |  _ \| |
#                             / __| | | | |_) | |
#                            | (__| |_| |  _ <| |___
#                             \___|\___/|_| \_\_____|
#
# Copyright (C) Viktor Szakats
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

# Bundle up individual tests into a single binary. The resulting binary can run
# individual tests by passing their name (without '.c') as the first argument.
#
# Usage: mk-bundle-server.pl [<server_c>]

use strict;
use warnings;

my @src;
foreach my $src (@ARGV) {
    push @src, $src;
}

print <<HEADER
/* !checksrc! disable COPYRIGHT all */

#define MEMDEBUG_NODEFINES
#define HEADER_CURL_MEMORY_H
#include "first.h"
HEADER
    ;

# TODO: Some of these might be subject for de-duplication or sync.
my @reused_symbols = (
    "ProcessRequest",
    "byteval",
    "config",
    "configfile",
    "configurable",
    "docquit",
    "get_request",
    "getconfig",
    "httprequest",
    "incoming",
    "ipv_inuse",
    "logdir",
    "loghex",
    "loglockfile",
    "parse_servercmd",
    "pidname",
    "portname",
    "prevbounce",
    "prevpartno",
    "prevtestno",
    "resetdefaults",
    "send_doc",
    "server_port",
    "serverlogslocked",
    "sockdaemon",
    "socket_domain",
    "socket_type",
    "storerequest",
    "use_ipv6",
    "wrotepidfile",
    "wroteportfile",
    );

# TODO: Some of these may be #undef-ed manually at the end of each source
my @reused_macros = (
    "DEFAULT_LOGFILE",
    "DEFAULT_PORT",
    "REQBUFSIZ",
    );

my $tlist = "";

foreach my $src (@src) {
    my $nams = $src;

    # Make common symbols unique across server sources
    foreach my $symb ("main", @reused_symbols) {
        print "#undef $symb\n";
        print "#define $symb ${symb}_$nams\n";
    }
    print "int main_$nams(int argc, char **argv);\n";
    print "#include \"$src.c\"\n";

    # Reset macros re-used by multiple servers
    foreach my $undef ("main", @reused_macros) {
        print "#undef $undef\n";
    }

    print "\n";

    $tlist .= "  {\"$nams\", main_$nams},\n";
}

print <<FOOTER
const struct onemain p_mains[] = {
${tlist}  {NULL, NULL}
};
FOOTER
    ;
