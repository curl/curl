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

# Update man pages.

use strict;
use warnings;
use Tie::File;

# Data from the command line.

my $curlver = $ARGV[0];
my $curldate = $ARGV[1];

# Directories and extensions.

my @dirlist = ("docs/", "docs/libcurl/", "docs/libcurl/opts/", "tests/");
my @extlist = (".1", ".3");
my @excludelist = ("mk-ca-bundle.1", "template.3");

# Subroutines

sub printargs{
  # Print arguments and exit.

  print "usage: updatemanpages.pl <version> <date>\n";
  exit;
}

sub getthline{
  # Process file looking for .TH section.

  my $filename = shift;
  my $file_handle;
  my $file_line;

  # Open the file.

  open($file_handle, $filename);

  # Look for the .TH section, process it into an array,
  # modify it and write to file.

  tie(my @file_data, 'Tie::File', $filename);
  foreach my $file_data_line(@file_data) {
    if($file_data_line =~ /^.TH/) {
      $file_line = $file_data_line;
      last;
    }
  }

  # Close the file.

  close($file_handle);
  return $file_line;
}

sub extractth{
  # Extract .TH section as an array.

  my $input = shift;

  # Split the line into an array.

  my @tharray;
  my $inputsize = length($input);
  my $inputcurrent = "";
  my $quotemode = 0;

  for(my $inputseek = 0; $inputseek < $inputsize; $inputseek++) {

    if(substr($input, $inputseek, 1) eq " " && $quotemode eq 0) {
      push(@tharray, $inputcurrent);
      $inputcurrent = "";
      next;
    }

    $inputcurrent = $inputcurrent . substr($input, $inputseek, 1);

    if(substr($input, $inputseek, 1) eq "\"") {
      if($quotemode eq 0) {
        $quotemode = 1;
      }
      else {
        $quotemode = 0;
      }
    }
  }

  if($inputcurrent ne "") {
    push(@tharray, $inputcurrent);
  }

  return @tharray;
}

sub getdate{
  # Get the date from the .TH section.

  my $filename = shift;
  my $thline;
  my @tharray;
  my $date = "";

  $thline = getthline($filename);

  # Return nothing if there is no .TH section found.

  if(!$thline || $thline eq "") {
    return "";
  }

  @tharray = extractth($thline);

  # Remove the quotes at the start and end.

  $date = substr($tharray[3], 1, -1);
  return $date;
}

sub processth{
  # Process .TH section.

  my $input = shift;
  my $date = shift;

  # Split the line into an array.

  my @tharray = extractth($input);

  # Alter the date.

  my $itemdate = "\"";
  $itemdate .= $date;
  $itemdate .= "\"";
  $tharray[3] = $itemdate;

  # Alter the item version.

  my $itemver = $tharray[4];
  my $itemname = "";

  for(my $itemnameseek = 1;
    $itemnameseek < length($itemver);
    $itemnameseek++) {
    if(substr($itemver, $itemnameseek, 1) eq " " ||
      substr($itemver, $itemnameseek, 1) eq "\"") {
      last;
    }
    $itemname .= substr($itemver, $itemnameseek, 1);
  }

  $itemver = "\"";
  $itemver .= $itemname;
  $itemver .= " ";
  $itemver .= $curlver;
  $itemver .= "\"";

  $tharray[4] = $itemver;

  my $thoutput = "";

  foreach my $thvalue (@tharray) {
    $thoutput .= $thvalue;
    $thoutput .= " ";
  }
  $thoutput =~ s/\s+$//;
  $thoutput .= "\n";

  # Return updated string.

  return $thoutput;
}

sub processfile{
  # Process file looking for .TH section.

  my $filename = shift;
  my $date = shift;
  my $file_handle;
  my $file_dist_handle;
  my $filename_dist;

  # Open a handle for the original file and a second file handle
  # for the dist file.

  $filename_dist = $filename . ".dist";

  open($file_handle, $filename);
  open($file_dist_handle, ">" . $filename_dist);

  # Look for the .TH section, process it into an array,
  # modify it and write to file.

  tie(my @file_data, 'Tie::File', $filename);
  foreach my $file_data_line (@file_data) {
    if($file_data_line =~ /^.TH/) {
      my $file_dist_line = processth($file_data_line, $date);
      print $file_dist_handle $file_dist_line . "\n";
    }
    else {
      print $file_dist_handle $file_data_line . "\n";
    }
  }

  # Close the file.

  close($file_handle);
  close($file_dist_handle);
}

# Check that $curlver is set, otherwise print arguments and exit.

if(!$curlver) {
  printargs();
}

# check to see that the git command works, it requires git 2.6 something
my $gitcheck = `git log -1 --date="format:%B %d, %Y" $dirlist[0] 2>/dev/null`;
if(length($gitcheck) < 1) {
    print "git version too old or $dirlist[0] is a bad argument\n";
    exit;
}

# Look in each directory.

my $dir_handle;

foreach my $dirname (@dirlist) {
  foreach my $extname (@extlist) {
    # Go through the directory looking for files ending with
    # the current extension.

    opendir($dir_handle, $dirname);
    my @filelist = grep(/.$extname$/i, readdir($dir_handle));

    foreach my $file (@filelist) {
      # Skip if file is in exclude list.

      if(grep(/^$file$/, @excludelist)) {
        next;
      }

      # Load the file and get the date.

      my $filedate;

      # Check if dist version exists and load date from that
      # file if it does.

      if(-e ($dirname . $file . ".dist")) {
        $filedate = getdate(($dirname . $file . ".dist"));
      }
      else {
        $filedate = getdate(($dirname . $file));
      }

      # Skip if value is empty.

      if(!$filedate || $filedate eq "") {
        next;
      }

      # Check the man page in the git repository.

      my $repodata = `LC_TIME=C git log -1 --date="format:%B %d, %Y" \\
                       --since="$filedate" $dirname$file | grep ^Date:`;

      # If there is output then update the man page
      # with the new date/version.

      # Process the file if there is output.

      if($repodata) {
        my $thisdate;
        if(!$curldate) {
          if($repodata =~ /^Date: +(.*)/) {
            $thisdate = $1;
          }
          else {
            print STDERR "Warning: " . ($dirname . $file) . ": found no " .
                           "date\n";
          }
        }
        else {
          $thisdate = $curldate;
        }
        processfile(($dirname . $file), $thisdate);
        print $dirname . $file . " page updated to $thisdate\n";
      }
    }
    closedir($dir_handle);
  }
}

__END__

=pod

=head1 updatemanpages.pl

Updates the man pages with the version number and optional date. If the date
isn't provided, the last modified date from git is used.

=head2 USAGE

updatemanpages.pl version [date]

=head3 version

Specifies version (required)

=head3 date

Specifies date (optional)

=head2 SETTINGS

=head3 @dirlist

Specifies the list of directories to look for files in.

=head3 @extlist

Specifies the list of files with extensions to process.

=head3 @excludelist

Specifies the list of files to not process.

=head2 NOTES

This script is used during maketgz.

=cut
