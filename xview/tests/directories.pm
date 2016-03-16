#***************************************************************************
#                                  _   _ ____  _
#  Project                     ___| | | |  _ \| |
#                             / __| | | | |_) | |
#                            | (__| |_| |  _ <| |___
#                             \___|\___/|_| \_\_____|
#
# Copyright (C) 1998 - 2011, Daniel Stenberg, <daniel@haxx.se>, et al.
#
# This software is licensed as described in the file COPYING, which
# you should have received as part of this distribution. The terms
# are also available at https://curl.haxx.se/docs/copyright.html.
#
# You may opt to use, copy, modify, merge, publish, distribute and/or sell
# copies of the Software, and permit persons to whom the Software is
# furnished to do so, under the terms of the COPYING file.
#
# This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
# KIND, either express or implied.
#
###########################################################################
%file_chmod1 = (
  'name'      => 'chmod1',
  'content'   => "This file should have permissions 444\n",
  'perm'      => 'r--r--r--',
  'time'      => 'Jan 11 10:00',
  'dostime'   => '01-11-10  10:00AM',
);

%file_chmod2 = (
  'name'      => 'chmod2',
  'content'   => "This file should have permissions 666\n",
  'perm'      => 'rw-rw-rw-',
  'time'      => 'Feb  1  8:00',
  'dostime'   => '02-01-10  08:00AM',
);

%file_chmod3 = (
  'name'      => 'chmod3',
  'content'   => "This file should have permissions 777\n",
  'perm'      => 'rwxrwxrwx',
  'time'      => 'Feb  1  8:00',
  'dostime'   => '02-01-10  08:00AM',
);

%file_chmod4 = (
  'type'      => 'd',
  'name'      => 'chmod4',
  'content'   => "This file should have permissions 001\n",
  'perm'      => '--S--S--t',
  'time'      => 'May  4  4:31',
  'dostime'   => '05-04-10  04:31AM'
);

%file_chmod5 = (
  'type'      => 'd',
  'name'      => 'chmod5',
  'content'   => "This file should have permissions 110\n",
  'perm'      => '--s--s--T',
  'time'      => 'May  4  4:31',
  'dostime'   => '05-04-10  04:31AM'
);

%link_link = (
  'type'      => 'l',
  'name'      => 'link -> file.txt',
  'size'      => '8',
  'perm'      => 'rwxrwxrwx',
  'time'      => 'Jan  6  4:42'
);

%link_link_absolute = (
  'type'      => 'l',
  'name'      => 'link_absolute -> /data/ftp/file.txt',
  'size'      => '15',
  'perm'      => 'rwxrwxrwx',
  'time'      => 'Jan  6  4:45'
);

%dir_dot = (
  'type'      => "d",
  'name'      => ".",
  'hlink'     => "4",
  'time'      => "Apr 27  5:12",
  'size'      => "20480",
  'dostime'   => "04-27-10  05:12AM",
  'perm'      => "rwxrwxrwx"
);

%dir_ddot = (
  'type'      => "d",
  'name'      => "..",
  'hlink'     => "4",
  'size'      => "20480",
  'time'      => "Apr 23  3:12",
  'dostime'   => "04-23-10  03:12AM",
  'perm'      => "rwxrwxrwx"
);

%dir_weirddir_txt = (
  'type'      => "d",
  'name'      => "weirddir.txt",
  'hlink'     => "2",
  'size'      => "4096",
  'time'      => "Apr 23  3:12",
  'dostime'   => "04-23-10  03:12AM",
  'perm'      => "rwxr-xrwx"
);

%dir_UNIX = (
  'type'      => "d",
  'name'      => "UNIX",
  'hlink'     => "11",
  'size'      => "4096",
  'time'      => "Nov 01  2008",
  'dostime'   => "11-01-08  11:11AM",
  'perm'      => "rwx--x--x"
);

%dir_DOS = (
  'type'      => "d",
  'name'      => "DOS",
  'hlink'     => "11",
  'size'      => "4096",
  'time'      => "Nov 01  2008",
  'dostime'   => "11-01-08  11:11AM",
  'perm'      => "rwx--x--x"
);

%dir_dot_NeXT = (
  'type'      => "d",
  'name'      => ".NeXT",
  'hlink'     => "4",
  'size'      => "4096",
  'time'      => "Jan 23  2:05",
  'dostime'   => "01-23-05  02:05AM",
  'perm'      => "rwxrwxrwx"
);

%file_empty_file_dat = (
  'name'      => "empty_file.dat",
  'content'   => "",
  'perm'      => "rw-r--r--",
  'time'      => "Apr 27 11:01",
  'dostime'   => "04-27-10  11:01AM"
);

%file_file_txt = (
  'name'      => "file.txt",
  'content'   => "This is content of file \"file.txt\"\n",
  'time'      => "Apr 27 11:01",
  'dostime'   => "04-27-10  11:01AM",
  'perm'      => "rw-r--r--"
);

%file_someothertext_txt = (
  'name'      => "someothertext.txt",
  'content'   => "Some junk ;-) This file does not really exist.\n",
  'time'      => "Apr 27 11:01",
  'dostime'   => "04-27-10  11:01AM",
  'perm'      => "rw-r--r--"
);

%lists = (
  '/fully_simulated/' => {
    'files'   => [ \%dir_dot, \%dir_ddot, \%dir_DOS, \%dir_UNIX ],
    'eol'     => "\r\n",
    'type'    => "unix"
  },
  '/fully_simulated/UNIX/' => {
    'files'   => [ \%dir_dot, \%dir_ddot,
                   \%file_chmod1, \%file_chmod2, \%file_chmod3, \%file_chmod4, \%file_chmod5,
                   \%file_empty_file_dat, \%file_file_txt,
                   \%link_link, \%link_link_absolute, \%dir_dot_NeXT,
                   \%file_someothertext_txt, \%dir_weirddir_txt ],
    'eol'     => "\r\n",
    'type'    => 'unix'
  },
  '/fully_simulated/DOS/' => {
    'files'   => [ \%dir_dot, \%dir_ddot,
                   \%file_chmod1, \%file_chmod2, \%file_chmod3, \%file_chmod4, \%file_chmod5,
                   \%file_empty_file_dat, \%file_file_txt,
                   \%dir_dot_NeXT, \%file_someothertext_txt, \%dir_weirddir_txt ],
    'eol'     => "\r\n",
    'type'    => 'dos'
  }
);

sub ftp_createcontent($) {
  my (%list) = @_;

  $type = $$list{'type'};
  $eol  = $$list{'eol'};
  $list_ref = $$list{'files'};

  my @diroutput;
  my @contentlist;
  if($type eq "unix") {
    for(@$list_ref) {
      my %file = %$_;
      my $line = "";
      my $ftype  = $file{'type'}  ? $file{'type'}  : "-";
      my $fperm  = $file{'perm'}  ? $file{'perm'}  : "rwxr-xr-x";
      my $fuser  = $file{'user'}  ? sprintf("%15s", $file{'user'})   : "ftp-default";
      my $fgroup = $file{'group'} ? sprintf("%15s", $file{'group'})  : "ftp-default";
      my $fsize = "";
      if($file{'type'} eq "d") {
        $fsize = $file{'size'} ? sprintf("%7s", $file{'size'}) : sprintf("%7d", 4096);
      }
      else {
        $fsize = sprintf("%7d", length $file{'content'});
      }
      my $fhlink = $file{'hlink'} ? sprintf("%4d",  $file{'hlink'})  : "   1";
      my $ftime  = $file{'time'}  ? sprintf("%10s", $file{'time'})   : "Jan 9  1933";
      push(@contentlist, "$ftype$fperm $fhlink $fuser $fgroup $fsize $ftime $file{'name'}$eol");
    }

    return @contentlist;
  }
  elsif($type =~ /^dos$/) {
    for(@$list_ref) {
      my %file = %$_;
      my $line = "";
      my $time = $file{'dostime'} ? $file{'dostime'} : "06-25-97  09:12AM";
      my $size_or_dir;
      if($file{'type'} =~ /^d$/) {
        $size_or_dir = "      <DIR>         ";
      }
      else {
        $size_or_dir = sprintf("%20d", length $file{'content'});
      }
      push(@contentlist, "$time $size_or_dir $file{'name'}$eol");
    }
    return @contentlist;
  }
}

sub wildcard_filesize($$) {
  my ($list_type, $file) = @_;
  $list = $lists{$list_type};
  if($list) {
    my $files = $list->{'files'};
    for(@$files) {
      my %f = %$_;
      if ($f{'name'} eq $file) {
        if($f{'content'}) {
          return length $f{'content'};
        }
        elsif ($f{'type'} ne "d"){
          return 0;
        }
        else {
          return -1;
        }
      }
    }
  }
  return -1;
}
sub wildcard_getfile($$) {
  my ($list_type, $file) = @_;
  $list = $lists{$list_type};
  if($list) {
    my $files = $list->{'files'};
    for(@$files) {
      my %f = %$_;
      if ($f{'name'} eq $file) {
        if($f{'content'}) {
          return (length $f{'content'}, $f{'content'});
        }
        elsif ($f{'type'} ne "d"){
          return (0, "");
        }
        else {
          return (-1, 0);
        }
      }
    }
  }
  return (-1, 0);
}

sub ftp_contentlist {
  my $listname = $_[0];
  $list = $lists{$listname};
  return ftp_createcontent(\$list);
}
