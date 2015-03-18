#!/usr/local/bin/perl
#***************************************************************************
#                                  _   _ ____  _
#  Project                     ___| | | |  _ \| |
#                             / __| | | | |_) | |
#                            | (__| |_| |  _ <| |___
#                             \___|\___/|_| \_\_____|
#
# Copyright (C) 1998 - 2014, Daniel Stenberg, <daniel@haxx.se>, et al.
#
# This software is licensed as described in the file COPYING, which
# you should have received as part of this distribution. The terms
# are also available at http://curl.haxx.se/docs/copyright.html.
#
# You may opt to use, copy, modify, merge, publish, distribute and/or sell
# copies of the Software, and permit persons to whom the Software is
# furnished to do so, under the terms of the COPYING file.
#
# This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
# KIND, either express or implied.
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

my $README = $ARGV[0];

if($README eq "") {
    print "usage: mkreadme.pl [-c] <README> < manpage\n";
    exit;
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

open(READ, "<$README") ||
    die "couldn't read the README infile $README";

while(<READ>) {
    my $line = $_;

    # remove trailing CR from line. msysgit checks out files as line+CRLF
    $line =~ s/\r$//;

    push @out, $line;
}
close(READ);

# if compressed
if($c) {
    my @test = `gzip --version 2>&1`;
    if($test[0] =~ /gzip/) {
        open(GZIP, ">dumpit") ||
            die "can't create the dumpit file, try without -c";
        binmode GZIP;
        for(@out) {
            print GZIP $_;
            $gzip += length($_);
        }
        close(GZIP);

        system("gzip --best --no-name dumpit");

        open(GZIP, "<dumpit.gz") ||
             die "can't read the dumpit.gz file, try without -c";
        binmode GZIP;
        while(<GZIP>) {
            push @gzip, $_;
            $gzipped += length($_);
        }
        close(GZIP);

        unlink("dumpit.gz");
    }
    else {
        # no gzip, no compression!
        undef $c;
        print STDERR "MEEEP: Couldn't find gzip, disable compression\n";
    }
}

$now = localtime;
print <<HEAD
/*
 * NEVER EVER edit this manually, fix the mkhelp.pl script instead!
 * Generation time: $now
 */
#ifdef USE_MANUAL
#include "tool_hugehelp.h"
HEAD
    ;
if($c) {
    print <<HEAD
#include <zlib.h>
#include "memdebug.h" /* keep this as LAST include */
static const unsigned char hugehelpgz[] = {
  /* This mumbo-jumbo is the huge help text compressed with gzip.
     Thanks to this operation, the size of this data shrunk from $gzip
     to $gzipped bytes. You can disable the use of compressed help
     texts by NOT passing -c to the mkhelp.pl tool. */
HEAD
;
    my $c=0;
    print " ";
    for(@gzip) {
        my @all=split(//, $_);
        for(@all) {
            my $num=ord($_);
            printf(" 0x%02x,", 0+$num);
            if(++$c>11) {
                print "\n ";
                $c=0;
            }
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
#else /* !USE_MANUAL */
/* built-in manual is disabled, blank function */
#include "tool_hugehelp.h"
void hugehelp(void) {}
#endif /* USE_MANUAL */
FOOT
  ;
}
