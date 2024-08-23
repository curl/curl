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
#
###########################################################################
#
# Check that the deprecated statuses of functions and enum values in header
# files, manpages and symbols-in-versions are in sync.

use strict;
use warnings;

use File::Basename;

my $root=$ARGV[0] || ".";
my $incdir = "$root/include/curl";
my $docdir = "$root/docs";
my $libdocdir = "$docdir/libcurl";
my $errcode = 0;

# Symbol-indexed hashes.
# Values are:
#     X       Not deprecated
#     ?       Deprecated in unknown version
#     x.yy.z  Deprecated in version x.yy.z
my %syminver;       # Symbols-in-versions deprecations.
my %hdr;            # Public header files deprecations.
my %funcman;        # Function manpages deprecations.
my %optman;         # Option manpages deprecations.


# Scan header file for public function and enum values. Flag them with
# the version they are deprecated in, if some.
sub scan_header {
    my ($f)=@_;
    my $line = "";
    my $incomment = 0;
    my $inenum = 0;

    open(my $h, "<", "$f");
    while(<$h>) {
      s/^\s*(.*?)\s*$/$1/;      # Trim.
      # Remove multi-line comment trail.
      if($incomment) {
        if($_ !~ /.*?\*\/\s*(.*)$/) {
          next;
        }
        $_ = $1;
        $incomment = 0;
      }
      if($line ne "") {
        # Unfold line.
        $_ = "$line $1";
        $line = "";
      }
      # Remove comments.
      while($_ =~ /^(.*?)\/\*.*?\*\/(.*)$/) {
        $_ = "$1 $2";
      }
      if($_ =~ /^(.*)\/\*/) {
        $_ = "$1 ";
        $incomment = 1;
      }
      s/^\s*(.*?)\s*$/$1/;      # Trim again.
      # Ignore preprocessor directives and blank lines.
      if($_ =~ /^(?:#|$)/) {
        next;
      }
      # Handle lines that may be continued as if they were folded.
      if($_ !~ /[;,{}]$/) {
        # Folded line.
        $line = $_;
        next;
      }
      if($_ =~ /CURLOPTDEPRECATED\(/) {
        # Handle deprecated CURLOPT_* option.
        if($_ !~ /CURLOPTDEPRECATED\(\s*(\S+)\s*,(?:.*?,){2}\s*(.*?)\s*,.*"\)/) {
          # Folded line.
          $line = $_;
          next;
        }
        $hdr{$1} = $2;
      }
      elsif($_ =~ /CURLOPT\(/) {
        # Handle non-deprecated CURLOPT_* option.
        if($_ !~ /CURLOPT\(\s*(\S+)\s*(?:,.*?){2}\)/) {
          # Folded line.
          $line = $_;
          next;
        }
        $hdr{$1} = "X";
      }
      else {
        my $version = "X";

        # Get other kind of deprecation from this line.
        if($_ =~ /CURL_DEPRECATED\(/) {
          if($_ !~ /^(.*)CURL_DEPRECATED\(\s*(\S+?)\s*,.*?"\)(.*)$/) {
            # Folded line.
            $line = $_;
            next;
          }
         $version = $2;
         $_ = "$1 $3";
        }
        if($_ =~ /^CURL_EXTERN\s+.*\s+(\S+?)\s*\(/) {
          # Flag public function.
          $hdr{$1} = $version;
        }
        elsif($inenum && $_ =~ /(\w+)\s*[,=}]/) {
          # Flag enum value.
          $hdr{$1} = $version;
        }
      }
      # Remember if we are in an enum definition.
      $inenum |= ($_ =~ /\benum\b/);
      if($_ =~ /}/) {
        $inenum = 0;
      }
    }
    close $h;
}

# Scan function manpage for options.
# Each option has to be declared as ".IP <option>" where <option> starts with
# the prefix. Flag each option with its deprecation version, if some.
sub scan_man_for_opts {
    my ($f, $prefix)=@_;
    my $opt = "";
    my $line = "";

    open(my $m, "<", "$f");
    while(<$m>) {
      if($_ =~ /^\./) {
        # roff directive found: end current option paragraph.
        my $o = $opt;
        $opt = "";
        if($_ =~ /^\.IP\s+((?:$prefix)_\w+)/) {
          # A new option has been found.
          $opt = $1;
        }
        $_ = $line;     # Get full paragraph.
        $line = "";
        s/\\f.//g;      # Remove font formatting.
        s/\s+/ /g;      # One line with single space only.
        if($o) {
          $funcman{$o} = "X";
          # Check if paragraph is mentioning deprecation.
          while($_ =~ /(?:deprecated|obsoleted?)\b\s*(?:in\b|since\b)?\s*(?:version\b|curl\b|libcurl\b)?\s*(\d[0-9.]*\d)?\b\s*(.*)$/i) {
            $funcman{$o} = $1 || "?";
            $_ = $2;
          }
        }
      }
      else {
        # Text line: accumulate.
        $line .= $_;
      }
    }
    close $m;
}

# Scan manpage for deprecation in DESCRIPTION and/or AVAILABILITY sections.
sub scan_man_page {
    my ($path, $sym, $table)=@_;
    my $version = "X";

    if(open(my $fh, "<", "$path")) {
      my $section = "";
      my $line = "";

      while(<$fh>) {
        if($_ =~ /\.so\s+man3\/(.*\.3\b)/) {
          # Handle manpage inclusion.
          scan_man_page(dirname($path) . "/$1", $sym, $table);
          $version = exists($$table{$sym})? $$table{$sym}: $version;
        }
        elsif($_ =~ /^\./) {
          # Line is a roff directive.
          if($_ =~ /^\.SH\b\s*(\w*)/) {
            # Section starts. End previous one.
            my $sh = $section;

            $section = $1;
            $_ = $line;     # Previous section text.
            $line = "";
            s/\\f.//g;
            s/\s+/ /g;
            s/\\f.//g;      # Remove font formatting.
            s/\s+/ /g;      # One line with single space only.
            if($sh =~ /DESCRIPTION|DEPRECATED/) {
              while($_ =~ /(?:deprecated|obsoleted?)\b\s*(?:in\b|since\b)?\s*(?:version\b|curl\b|libcurl\b)?\s*(\d[0-9.]*\d)?\b\s*(.*)$/i) {
                # Flag deprecation status.
                if($version ne "X" && $version ne "?") {
                  if($1 && $1 ne $version) {
                    print "error: $sym manpage lists unmatching deprecation versions $version and $1\n";
                    $errcode++;
                  }
                }
                else {
                  $version = $1 || "?";
                }
                $_ = $2;
              }
            }
          }
        }
        else {
          # Text line: accumulate.
          $line .= $_;
        }
      }
      close $fh;
      $$table{$sym} = $version;
    }
}


# Read symbols-in-versions.
open(my $fh, "<", "$libdocdir/symbols-in-versions") ||
  die "$libdocdir/symbols-in-versions";
while(<$fh>) {
  if($_ =~ /^((?:CURL|LIBCURL)\S+)\s+\S+\s*(\S*)\s*(\S*)$/) {
    if($3 eq "") {
      $syminver{$1} = "X";
      if($2 ne "" && $2 ne ".") {
        $syminver{$1} = $2;
      }
    }
  }
}
close($fh);

# Get header file names,
opendir(my $dh, $incdir) || die "Can't opendir $incdir";
my @hfiles = grep { /\.h$/ } readdir($dh);
closedir $dh;

# Get functions and enum symbols from header files.
for(@hfiles) {
  scan_header("$incdir/$_");
}

# Get function statuses from manpages.
foreach my $sym (keys %hdr) {
  if($sym =~/^(?:curl|curlx)_\w/) {
    scan_man_page("$libdocdir/$sym.3", $sym, \%funcman);
  }
}

# Get options from function manpages.
scan_man_for_opts("$libdocdir/curl_easy_setopt.3", "CURLOPT");
scan_man_for_opts("$libdocdir/curl_easy_getinfo.3", "CURLINFO");

# Get deprecation status from option manpages.
foreach my $sym (keys %syminver) {
  if($sym =~ /^(?:CURLOPT|CURLINFO)_\w+$/) {
    scan_man_page("$libdocdir/opts/$sym.3", $sym, \%optman);
  }
}

# Print results.
my %keys = (%syminver, %funcman, %optman, %hdr);
my $leader = <<HEADER
Legend:
<empty> Not listed
X       Not deprecated
?       Deprecated in unknown version
x.yy.z  Deprecated in version x.yy.z

Symbol                                 symbols-in  func man  opt man   .h
                                       -versions
HEADER
        ;
foreach my $sym (sort {$a cmp $b} keys %keys) {
  if($sym =~ /^(?:CURLOPT|CURLINFO|curl|curlx)_\w/) {
    my $s = exists($syminver{$sym})? $syminver{$sym}: " ";
    my $f = exists($funcman{$sym})? $funcman{$sym}: " ";
    my $o = exists($optman{$sym})? $optman{$sym}: " ";
    my $h = exists($hdr{$sym})? $hdr{$sym}: " ";
    my $r = " ";

    # There are deprecated symbols in symbols-in-versions that are aliases
    # and thus not listed anywhere else. Ignore them.
    "$f$o$h" =~ /[X ]{3}/ && next;

    # Check for inconsistencies between deprecations from the different sources.
    foreach my $k ($s, $f, $o, $h) {
      $r = $r eq " "? $k: $r;
      if($k ne " " && $r ne $k) {
        if($r eq "?") {
          $r = $k ne "X"? $k: "!";
        }
        elsif($r eq "X" || $k ne "?") {
          $r = "!";
        }
      }
    }

    if($r eq "!") {
      print $leader;
      $leader = "";
      printf("%-38s %-11s %-9s %-9s %s\n", $sym, $s, $f, $o, $h);
      $errcode++;
    }
  }
}

exit $errcode;
