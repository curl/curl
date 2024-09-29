###########################################################################
#                                  _   _ ____  _
#  Project                     ___| | | |  _ \| |
#                             / __| | | | |_) | |
#                            | (__| |_| |  _ <| |___
#                             \___|\___/|_| \_\_____|
#
# Copyright (C) Evgeny Grin (Karlson2k), <k2k@narod.ru>.
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

# This Perl package helps with path transforming when running curl tests on
# Windows platform with MSYS or Cygwin.
# Three main functions 'sys_native_abs_path' and
# 'build_sys_abs_path' autodetect format of given pathnames. Following formats
# are supported:
#  (1) /some/path   - absolute path in Unix-style
#  (2) D:/some/path - absolute path in Windows-style
#  (3) some/path    - relative path
#  (4) D:some/path  - path relative to current directory on Windows drive
#                     (paths like 'D:' are treated as 'D:./') (*)
#  (5) \some/path   - path from root directory on current Windows drive (*)
# All forward '/' and back '\' slashes are treated identically except leading
# slash in forms (1) and (5).
# Forward slashes are simpler processed in Perl, do not require extra escaping
# for shell (unlike back slashes) and accepted by Windows native programs, so
# all functions return paths with only forward slashes.
# All returned paths don't contain any duplicated slashes, only single slashes
# are used as directory separators on output.
# On non-Windows platforms functions acts as transparent wrappers for similar
# Perl's functions or return unmodified string (depending on functionality),
# so all functions can be unconditionally used on all platforms.
#
# (*) CAUTION! Forms (4) and (5) are not recommended to use as they can be
#     interpreted incorrectly in Perl and MSYS/Cygwin environment have low
#     control on Windows current drive and Windows current path on specific
#     drive.

package pathhelp;

use strict;
use warnings;
use Cwd 'abs_path';

BEGIN {
    use base qw(Exporter);

    our @EXPORT_OK = qw(
        os_is_win
        exe_ext
        sys_native_abs_path
        sys_native_current_path
        build_sys_abs_path
        normalize_path
        drives_mounted_on_cygdrive
    );
}


#######################################################################
# Block for cached static variables
#
{
    # Cached static variable, Perl 5.0-compatible.
    my $is_win = $^O eq 'MSWin32'
              || $^O eq 'cygwin'
              || $^O eq 'msys';

    # Returns boolean true if OS is any form of Windows.
    sub os_is_win {
        return $is_win;
    }

    # Cached static variable, Perl 5.0-compatible.
    my $cygdrive_present;

    # Returns boolean true if Windows drives mounted with '/cygdrive/' prefix.
    sub drives_mounted_on_cygdrive {
        return $cygdrive_present if defined $cygdrive_present;
        $cygdrive_present = ((-e '/cygdrive/') && (-d '/cygdrive/')) ? 1 : 0;
        return $cygdrive_present;
    }
}

#######################################################################
# Performs path "normalization": all slashes converted to forward
# slashes (except leading slash), all duplicated slashes are replaced
# with single slashes, all relative directories ('./' and '../') are
# resolved if possible.
# Path processed as string, directories are not checked for presence so
# path for not yet existing directory can be "normalized".
#
sub normalize_path;

#######################################################################
# Returns current working directory in Windows format on Windows.
#
sub sys_native_current_path {
    return Cwd::getcwd() if !os_is_win();

    my $cur_dir;
    if($^O eq 'MSWin32') {
        $cur_dir = Cwd::getcwd();
    }
    else {
        $cur_dir = Cygwin::posix_to_win_path(Cwd::getcwd());
    }
    print "sys_native_current_path: $^O: Return: '$cur_dir'\n";
    return $cur_dir;
}

#######################################################################
# Converts given path to system native absolute path, i.e. to Windows
# absolute format on Windows platform. Both relative and absolute
# formats are supported for input.
#
sub sys_native_abs_path {
    my ($path) = @_;

    # Return untouched on non-Windows platforms.
    return Cwd::abs_path($path) if !os_is_win();

    # Do not process empty path.
    return $path if ($path eq '');

    my $new;
    if($^O eq 'msys' || $^O eq 'cygwin') {
        $new = Cygwin::posix_to_win_path(Cwd::abs_path($path));
    }
    elsif($path =~ m{^/(cygdrive/)?([a-z])/(.*)}) {
        $new = uc($2) . ":/" . $3;
    }
    else {
        $new = Cwd::abs_path($path);
    }

    print "sys_native_abs_path: $^O: Return: '$path' -> '$new'\n";
    return $new;
}

#######################################################################
# Converts given path to build system format absolute path, i.e. to
# MSYS/Cygwin Unix-style absolute format on Windows platform. Both
# relative and absolute formats are supported for input.
#
sub build_sys_abs_path {
    my ($path) = @_;

    # Return untouched on non-Windows platforms.
    return Cwd::abs_path($path) if !os_is_win();

    my $new;
    if($^O eq 'msys' || $^O eq 'cygwin') {
        $new = Cygwin::win_to_posix_path($path, 1);
    }
    else {
        $new = normalize_path(Cwd::abs_path($path));

        if($new =~ m{^([A-Za-z]):(.*)}) {
            $new = "/" . lc($1) . $2;
            $new = '/cygdrive' . $new if(drives_mounted_on_cygdrive());
        }
    }

    print "build_sys_abs_path: $^O: Return: '$path' -> '$new'\n";
    return $new;
}

#######################################################################
# Performs path "normalization": all slashes converted to forward
# slashes (except leading slash), all duplicated slashes are replaced
# with single slashes, all relative directories ('./' and '../') are
# resolved if possible.
# Path processed as string, directories are not checked for presence so
# path for not yet existing directory can be "normalized".
#
sub normalize_path {
    my ($path) = @_;

    # Don't process empty paths.
    return $path if $path eq '';

    if($path !~ m{(?:^|\\|/)\.{1,2}(?:\\|/|$)}) {
        # Speed up processing of simple paths.
        my $first_char = substr($path, 0, 1);
        $path =~ s{[\\/]+}{/}g;
        # Restore starting backslash if any.
        substr($path, 0, 1, $first_char);
        return $path;
    }

    my @arr;
    my $prefix;
    my $have_root = 0;

    # Check whether path starts from Windows drive. ('C:path' or 'C:\path')
    if($path =~ m{^([a-zA-Z]:(/|\\)?)(.*$)}) {
        $prefix = $1;
        $have_root = 1 if defined $2;
        # Process path separately from drive letter.
        @arr = split(m{\/|\\}, $3);
        # Replace backslash with forward slash if required.
        substr($prefix, 2, 1, '/') if $have_root;
    }
    else {
        if($path =~ m{^(\/|\\)}) {
            $have_root = 1;
            $prefix = $1;
        }
        else {
            $prefix = '';
        }
        @arr = split(m{\/|\\}, $path);
    }

    my $p = 0;
    my @res;

    for my $el (@arr) {
        if(length($el) == 0 || $el eq '.') {
            next;
        }
        elsif($el eq '..' && @res > 0 && $res[-1] ne '..') {
            pop @res;
            next;
        }
        push @res, $el;
    }
    if($have_root && @res > 0 && $res[0] eq '..') {
        warn "Error processing path \"$path\": " .
             "Parent directory of root directory does not exist!\n";
        return undef;
    }

    my $ret = $prefix . join('/', @res);
    $ret .= '/' if($path =~ m{\\$|/$} && scalar @res > 0);

    return $ret;
}
#
#***************************************************************************
# Return file extension for executable files on this operating system
#
sub exe_ext {
    my ($component, @arr) = @_;
    if ($ENV{'CURL_TEST_EXE_EXT'}) {
        return $ENV{'CURL_TEST_EXE_EXT'};
    }
    if ($ENV{'CURL_TEST_EXE_EXT_'.$component}) {
        return $ENV{'CURL_TEST_EXE_EXT_'.$component};
    }
    if ($^O eq 'MSWin32' || $^O eq 'cygwin' || $^O eq 'msys' ||
        $^O eq 'dos' || $^O eq 'os2') {
        return '.exe';
    }
    return '';
}

1;    # End of module
