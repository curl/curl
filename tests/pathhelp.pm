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
# native Windows and MSYS/Cygwin.
# Following input formats are supported (via built-in Perl functions):
#  (1) /some/path   - absolute path in POSIX-style
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
use File::Spec;

BEGIN {
    use base qw(Exporter);

    our @EXPORT_OK = qw(
        os_is_win
        exe_ext
        dirsepadd
        sys_native_abs_path
        sys_native_current_path
        build_sys_abs_path
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
    $cur_dir =~ s{[/\\]+}{/}g;
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
    return File::Spec->rel2abs($path) if !os_is_win();

    # Do not process empty path.
    return $path if ($path eq '');

    my $res;
    if($^O eq 'msys' || $^O eq 'cygwin') {
        $res = Cygwin::posix_to_win_path(File::Spec->rel2abs($path));
    }
    elsif($path =~ m{^/(cygdrive/)?([a-z])/(.*)}) {
        $res = uc($2) . ":/" . $3;
    }
    else {
        $res = File::Spec->rel2abs($path);
    }

    $res =~ s{[/\\]+}{/}g;
    return $res;
}

#######################################################################
# Converts given path to build system format absolute path, i.e. to
# MSYS/Cygwin POSIX-style absolute format on Windows platform. Both
# relative and absolute formats are supported for input.
#
sub build_sys_abs_path {
    my ($path) = @_;

    # Return untouched on non-Windows platforms.
    return File::Spec->rel2abs($path) if !os_is_win();

    my $res;
    if($^O eq 'msys' || $^O eq 'cygwin') {
        $res = Cygwin::win_to_posix_path($path, 1);
    }
    else {
        $res = File::Spec->rel2abs($path);

        if($res =~ m{^([A-Za-z]):(.*)}) {
            $res = "/" . lc($1) . $2;
            $res = '/cygdrive' . $res if(drives_mounted_on_cygdrive());
        }
    }

    return $res;
}

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

#***************************************************************************
# Add ending slash if missing
#
sub dirsepadd {
    my ($dir) = @_;
    $dir =~ s/\/$//;
    return $dir . '/';
}

1;    # End of module
