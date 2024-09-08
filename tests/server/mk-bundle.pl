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
# Usage: mk-bundle.pl [<server_c>]

use strict;
use warnings;

my @src;
foreach my $src (@ARGV) {
    push @src, $src;
}

print <<HEADER
/* !checksrc! disable COPYRIGHT all */

#include "first.h"

HEADER
    ;

my $tlist = "";

foreach my $src (@src) {
    if($src =~ /\.c$/) {
        # Misc .c source to include
        print "#include \"$src\"\n\n";
    }
    elsif($src !~ /\.h$/) {
        # Make 'main' unique across server sources
        print "#undef main\n";
        print "#define main main_$src\n";
        print "int main_$src(int argc, char **argv);\n";
        print "#include \"$src.c\"\n";
        print "#undef main\n";
        print "\n";
        $tlist .= "  {\"$src\", main_$src},\n";
    }
}

print <<FOOTER
static const struct onemain s_mains[] = {
${tlist}  {NULL, NULL}
};

#include "first.c"
FOOTER
    ;
