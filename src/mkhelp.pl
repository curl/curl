#!/usr/bin/env perl
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

use strict;
use warnings;

my $c = 0;
if(@ARGV && $ARGV[0] eq "-c") {
    $c = 1;
    shift @ARGV;
}

my @out;

push @out, "          _   _ ____  _\n";
push @out, "      ___| | | |  _ \\| |\n";
push @out, "     / __| | | | |_) | |\n";
push @out, "    | (__| |_| |  _ <| |___\n";
push @out, "     \\___|\\___/|_| \\_\\_____|\n";

while(<STDIN>) {
    my $line = $_;
    push @out, $line;
}

print <<HEAD
/*
 * NEVER EVER edit this manually, fix the mkhelp.pl script instead!
 */
#include "tool_hugehelp.h"
#ifdef USE_MANUAL
#include "tool_help.h"

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
    print STDERR "Warning: compression requested but Gzip is not available\n" if(!$c)
}

if($c)
{
    my $content = join("", @out);
    my $gzippedContent;
    IO::Compress::Gzip::gzip(
        \$content, \$gzippedContent, Level => 9, TextFlag => 1, Time=>0) or die "gzip failed:";
    my $gzip = length($content);
    my $gzipped = length($gzippedContent);

    print <<HEAD
#include <zlib.h>
#include <memdebug.h> /* keep this as LAST include */
static const unsigned char hugehelpgz[] = {
  /* This mumbo-jumbo is the huge help text compressed with gzip.
     Thanks to this operation, the size of this data shrank from $gzip
     to $gzipped bytes. You can disable the use of compressed help
     texts by NOT passing -c to the mkhelp.pl tool. */
HEAD
;

    my $c=0;
    for(split(//, $gzippedContent)) {
        my $num=ord($_);
        if(!($c % 12)) {
            print " ";
        }
        printf(" 0x%02x,", 0+$num);
        if(!(++$c % 12)) {
            print "\n";
        }
    }
    print "\n};\n";

    print <<EOF
#define BUF_SIZE 0x10000
static voidpf zalloc_func(voidpf opaque, unsigned int items, unsigned int size)
{
  (void)opaque;
  /* not a typo, keep it calloc() */
  return (voidpf) calloc(items, size);
}
static void zfree_func(voidpf opaque, voidpf ptr)
{
  (void)opaque;
  free(ptr);
}

#define HEADERLEN 10

/* Decompress and send to stdout a gzip-compressed buffer */
void hugehelp(void)
{
  unsigned char *buf;
  int status;
  z_stream z;

  /* Make sure no gzip options are set */
  if(hugehelpgz[3] & 0xfe)
    return;

  memset(&z, 0, sizeof(z_stream));
  z.zalloc = (alloc_func)zalloc_func;
  z.zfree = (free_func)zfree_func;
  z.avail_in = (uInt)(sizeof(hugehelpgz) - HEADERLEN);
  z.next_in = (z_const Bytef *)hugehelpgz + HEADERLEN;

  if(inflateInit2(&z, -MAX_WBITS) != Z_OK)
    return;

  buf = malloc(BUF_SIZE);
  if(buf) {
    while(1) {
      z.avail_out = BUF_SIZE;
      z.next_out = buf;
      status = inflate(&z, Z_SYNC_FLUSH);
      if(status == Z_OK || status == Z_STREAM_END) {
        fwrite(buf, BUF_SIZE - z.avail_out, 1, stdout);
        if(status == Z_STREAM_END)
          break;
      }
      else
        break;    /* error */
    }
    free(buf);
  }
  inflateEnd(&z);
}
/* Show the help text for the 'arg' curl argument on stdout */
void showhelp(const char *trigger, const char *arg, const char *endarg)
{
  unsigned char *buf;
  int status;
  z_stream z;
  struct scan_ctx ctx;
  inithelpscan(&ctx, trigger, arg, endarg);

  /* Make sure no gzip options are set */
  if(hugehelpgz[3] & 0xfe)
    return;

  memset(&z, 0, sizeof(z_stream));
  z.zalloc = (alloc_func)zalloc_func;
  z.zfree = (free_func)zfree_func;
  z.avail_in = (uInt)(sizeof(hugehelpgz) - HEADERLEN);
  z.next_in = (z_const Bytef *)hugehelpgz + HEADERLEN;

  if(inflateInit2(&z, -MAX_WBITS) != Z_OK)
    return;

  buf = malloc(BUF_SIZE);
  if(buf) {
    while(1) {
      z.avail_out = BUF_SIZE;
      z.next_out = buf;
      status = inflate(&z, Z_SYNC_FLUSH);
      if(status == Z_OK || status == Z_STREAM_END) {
        size_t len = BUF_SIZE - z.avail_out;
        if(!helpscan(buf, len, &ctx))
          break;
        if(status == Z_STREAM_END)
          break;
      }
      else
        break;    /* error */
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
static const char * const curlman[] = {
HEAD
        ;
}

my $blank;
for my $n (@out) {
    chomp $n;
    $n =~ s/\\/\\\\/g;
    $n =~ s/\"/\\\"/g;
    $n =~ s/\t/\\t/g;

    if(!$n) {
        $blank++;
    }
    else {
        $n =~ s/        /\\t/g;
        printf("  \"%s%s\",\n", $blank?"\\n":"", $n);
        $blank = 0;
    }
}

print <<ENDLINE
  NULL
};
void hugehelp(void)
{
  int i = 0;
  while(curlman[i])
    puts(curlman[i++]);
}

/* Show the help text for the 'arg' curl argument on stdout */
void showhelp(const char *trigger, const char *arg, const char *endarg)
{
  int i = 0;
  struct scan_ctx ctx;
  inithelpscan(&ctx, trigger, arg, endarg);
  while(curlman[i]) {
    size_t len = strlen(curlman[i]);
    if(!helpscan((const unsigned char *)curlman[i], len, &ctx) ||
       !helpscan((const unsigned char *)"\\n", 1, &ctx))
      break;
    i++;
  }
}
ENDLINE
    ;

foot();

sub foot {
    print <<FOOT
#endif /* USE_MANUAL */
FOOT
  ;
}
