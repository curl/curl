#!/usr/bin/env perl
#***************************************************************************
#                                  _   _ ____  _
#  Project                     ___| | | |  _ \| |
#                             / __| | | | |_) | |
#                            | (__| |_| |  _ <| |___
#                             \___|\___/|_| \_\_____|
#
# Copyright (C) 1998 - 2022, Daniel Stenberg, <daniel@haxx.se>, et al.
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

# Yeah, I know, probably 1000 other persons already wrote a script like
# this, but I'll tell ya:

# THEY DON'T FIT ME :-)

# Get readme file as parameter:

if($ARGV[0] eq "-c") {
    $c=1;
    shift @ARGV;
}

push @out, "                                  _   _ ____  _\n";
push @out, "  Project                     ___| | | |  _ \\| |\n";
push @out, "                             / __| | | | |_) | |\n";
push @out, "                            | (__| |_| |  _ <| |___\n";
push @out, "                             \\___|\\___/|_| \\_\\_____|\n";

my $olen=0;
while (<STDIN>) {
    my $line = $_;

    # this should be removed:
    $line =~ s/(.|_)//g;

    # remove trailing CR from line. msysgit checks out files as line+CRLF
    $line =~ s/\r$//;

    if($line =~ /^([ \t]*\n|curl)/i) {
        # cut off headers and empty lines
        $wline++; # count number of cut off lines
        next;
    }

    my $text = $line;
    $text =~ s/^\s+//g; # cut off preceding...
    $text =~ s/\s+$//g; # and trailing whitespaces

    $tlen = length($text);

    if($wline && ($olen == $tlen)) {
        # if the previous line with contents was exactly as long as
        # this line, then we ignore the newlines!

        # We do this magic because a header may abort a paragraph at
        # any line, but we don't want that to be noticed in the output
        # here
        $wline=0;
    }
    $olen = $tlen;

    if($wline) {
        # we only make one empty line max
        $wline = 0;
        push @out, "\n";
    }
    push @out, $line;
}
push @out, "\n"; # just an extra newline

print <<HEAD
/*
 * NEVER EVER edit this manually, fix the mkhelp.pl script instead!
 */
#ifdef USE_MANUAL
#include "tool_hugehelp.h"
HEAD
    ;
if($c) {
    # If compression requested, check that the Gzip module is available
    # or else disable compression
    $c = eval
    {
      require IO::Compress::Gzip;
      IO::Compress::Gzip->import();
      1;
    };
    print STDERR "Warning: compression requested but Gzip is not available\n" if (!$c)
}

if($c)
{
    my $content = join("", @out);
    my $gzippedContent;
    IO::Compress::Gzip::gzip(
        \$content, \$gzippedContent, Level => 9, TextFlag => 1, Time=>0) or die "gzip failed:";
    $gzip = length($content);
    $gzipped = length($gzippedContent);

    print <<HEAD
#include <zlib.h>
#include "memdebug.h" /* keep this as LAST include */
static const unsigned char hugehelpgz[] = {
  /* This mumbo-jumbo is the huge help text compressed with gzip.
     Thanks to this operation, the size of this data shrank from $gzip
     to $gzipped bytes. You can disable the use of compressed help
     texts by NOT passing -c to the mkhelp.pl tool. */
HEAD
;

    my $c=0;
    print " ";
    for(split(//, $gzippedContent)) {
        my $num=ord($_);
        printf(" 0x%02x,", 0+$num);
        if(!(++$c % 12)) {
            print "\n ";
        }
    }
    print "\n};\n";

    print <<EOF
#define BUF_SIZE 0x10000
static voidpf zalloc_func(voidpf opaque, unsigned int items, unsigned int size)
{
  (void) opaque;
  /* not a typo, keep it calloc() */
  return (voidpf) calloc(items, size);
}
static void zfree_func(voidpf opaque, voidpf ptr)
{
  (void) opaque;
  free(ptr);
}
/* Decompress and send to stdout a gzip-compressed buffer */
void hugehelp(void)
{
  unsigned char* buf;
  int status,headerlen;
  z_stream z;

  /* Make sure no gzip options are set */
  if (hugehelpgz[3] & 0xfe)
    return;

  headerlen = 10;
  memset(&z, 0, sizeof(z_stream));
  z.zalloc = (alloc_func)zalloc_func;
  z.zfree = (free_func)zfree_func;
  z.avail_in = (unsigned int)(sizeof(hugehelpgz) - headerlen);
  z.next_in = (unsigned char *)hugehelpgz + headerlen;

  if (inflateInit2(&z, -MAX_WBITS) != Z_OK)
    return;

  buf = malloc(BUF_SIZE);
  if (buf) {
    while(1) {
      z.avail_out = BUF_SIZE;
      z.next_out = buf;
      status = inflate(&z, Z_SYNC_FLUSH);
      if (status == Z_OK || status == Z_STREAM_END) {
        fwrite(buf, BUF_SIZE - z.avail_out, 1, stdout);
        if (status == Z_STREAM_END)
          break;
      }
      else
        break;    /* Error */
    }
    free(buf);
  }
  inflateEnd(&z);
}
EOF
    ;
foot();
exit;
}
else {
    print <<HEAD
void hugehelp(void)
{
   fputs(
HEAD
         ;
}

$outsize=0;
for(@out) {
    chop;

    $new = $_;

    $outsize += length($new)+1; # one for the newline

    $new =~ s/\\/\\\\/g;
    $new =~ s/\"/\\\"/g;

    # gcc 2.96 claims ISO C89 only is required to support 509 letter strings
    if($outsize > 500) {
        # terminate and make another fputs() call here
        print ", stdout);\n fputs(\n";
        $outsize=length($new)+1;
    }
    printf("\"%s\\n\"\n", $new);

}

print ", stdout) ;\n}\n";

foot();

sub foot {
  print <<FOOT
#endif /* USE_MANUAL */
FOOT
  ;
}
