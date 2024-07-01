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

# Yeah, I know, probably 1000 other persons already wrote a script like
# this, but I'll tell ya:

# THEY DON'T FIT ME :-)

# Get readme file as parameter:

if($ARGV[0] eq "-c") {
    $c=1;
    shift @ARGV;
}

push @out, "          _   _ ____  _\n";
push @out, "      ___| | | |  _ \\| |\n";
push @out, "     / __| | | | |_) | |\n";
push @out, "    | (__| |_| |  _ <| |___\n";
push @out, "     \\___|\\___/|_| \\_\\_____|\n";

my $olen=0;
while (<STDIN>) {
    my $line = $_;
    push @out, $line;
}

print <<HEAD
/*
 * NEVER EVER edit this manually, fix the mkhelp.pl script instead!
 */
#ifdef USE_MANUAL
#include "tool_hugehelp.h"


struct scan_ctx {
  const char *arg;
  size_t flen;
  const char *endarg;
  size_t elen;
  size_t olen;
  char rbuf[80];
  char obuf[80];
  bool show;
};

static void initscan(struct scan_ctx *ctx,
                     const char *arg,
                     const char *endarg)
{
  ctx->arg = arg;
  ctx->flen = strlen(arg);
  ctx->endarg = endarg;
  ctx->elen = strlen(endarg);
  ctx->show = FALSE;
  ctx->olen = 0;
  memset(ctx->rbuf, 0, sizeof(ctx->rbuf));
}

static bool scanfor(unsigned char *buf, size_t len, struct scan_ctx *ctx)
{
  size_t i;
  for(i = 0; i < len; i++) {
    if(!ctx->show) {
      memmove(&ctx->rbuf[0], &ctx->rbuf[1], ctx->flen - 1);
      ctx->rbuf[ctx->flen - 1] = buf[i];
      if(!memcmp(ctx->rbuf, ctx->arg, ctx->flen)) {
        /* match, now output until endarg */
        fputs(&ctx->arg[1], stdout);
        ctx->show = TRUE;
      }
      continue;
    }

    /* show until the end */
    memmove(&ctx->rbuf[0], &ctx->rbuf[1], ctx->elen - 1);
    ctx->rbuf[ctx->elen - 1] = buf[i];
    if(!memcmp(ctx->rbuf, ctx->endarg, ctx->elen))
      return FALSE;

    if(buf[i] == \'\\n\') {
      ctx->obuf[ctx->olen++] = 0;
      ctx->olen = 0;
      puts(ctx->obuf);
    }
    else
      ctx->obuf[ctx->olen++] = buf[i];
  }
  return TRUE;
}

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
  z.avail_in = (unsigned int)(sizeof(hugehelpgz) - HEADERLEN);
  z.next_in = (unsigned char *)hugehelpgz + HEADERLEN;

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
void showhelp(const char *arg, const char *endarg)
{
  unsigned char *buf;
  int status;
  z_stream z;
  struct scan_ctx ctx;
  initscan(&ctx, arg, endarg);

  /* Make sure no gzip options are set */
  if(hugehelpgz[3] & 0xfe)
    return;

  memset(&z, 0, sizeof(z_stream));
  z.zalloc = (alloc_func)zalloc_func;
  z.zfree = (free_func)zfree_func;
  z.avail_in = (unsigned int)(sizeof(hugehelpgz) - HEADERLEN);
  z.next_in = (unsigned char *)hugehelpgz + HEADERLEN;

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
        if(!scanfor(buf, len, &ctx))
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
void showhelp(const char *arg, const char *endarg)
{
  int i = 0;
  struct scan_ctx ctx;
  initscan(&ctx, arg, endarg);
  while(curlman[i]) {
    size_t len = strlen(curlman[i]);
    if(!scanfor((unsigned char *)curlman[i], len, &ctx) ||
       !scanfor((unsigned char *)"\\n", 1, &ctx))
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
