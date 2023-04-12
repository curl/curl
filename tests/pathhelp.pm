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
# Win32 platform with Msys or Cygwin.
# Three main functions 'sys_native_abs_path', 'sys_native_path' and
# 'build_sys_abs_path' autodetect format of given pathnames. Following formats
# are supported:
#  (1) /some/path   - absolute path in Unix-style
#  (2) D:/some/path - absolute path in Win32-style
#  (3) some/path    - relative path
#  (4) D:some/path  - path relative to current directory on Win32 drive (paths
#                     like 'D:' are treated as 'D:./') (*)
#  (5) \some/path   - path from root directory on current Win32 drive (*)
# All forward '/' and back '\' slashes are treated identically except leading
# slash in forms (1) and (5).
# Forward slashes are simpler processed in Perl, do not require extra escaping
# for shell (unlike back slashes) and accepted by Win32 native programs, so
# all functions return paths with only forward slashes except
# 'sys_native_path' which returns paths with first forward slash for form (5).
# All returned paths don't contain any duplicated slashes, only single slashes
# are used as directory separators on output.
# On non-Windows platforms functions acts as transparent wrappers for similar
# Perl's functions or return unmodified string (depending on functionality),
# so all functions can be unconditionally used on all platforms.
#
# (*) CAUTION! Forms (4) and (5) are not recommended to use as they can be
#     interpreted incorrectly in Perl and Msys/Cygwin environment have low
#     control on Win32 current drive and Win32 current path on specific drive.

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
        should_use_cygpath
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

    # Returns boolean true if Win32 drives mounted with '/cygdrive/' prefix.
    sub drives_mounted_on_cygdrive {
        return $cygdrive_present if defined $cygdrive_present;
        $cygdrive_present = ((-e '/cygdrive/') && (-d '/cygdrive/')) ? 1 : 0;
        return $cygdrive_present;
    }
}

my $use_cygpath;     # Only for Win32:
                     #  undef - autodetect
                     #      0 - do not use cygpath
                     #      1 - use cygpath

# Returns boolean true if 'cygpath' utility should be used for path conversion.
sub should_use_cygpath {
    return $use_cygpath if defined $use_cygpath;
    if(os_is_win()) {
        $use_cygpath = (qx{cygpath -u '.\\' 2>/dev/null} eq "./\n" && $? == 0);
    } else {
        $use_cygpath = 0;
    }
    return $use_cygpath;
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
# Returns current working directory in Win32 format on Windows.
#
sub sys_native_current_path {
    return Cwd::getcwd() if !os_is_win();

    my $cur_dir;
    if($^O eq 'msys') {
        # MSys shell has built-in command.
        chomp($cur_dir = `bash -c 'pwd -W'`);
        if($? != 0) {
            warn "Can't determine Win32 current directory.\n";
            return undef;
        }
        # Add final slash if required.
        $cur_dir .= '/' if length($cur_dir) > 3;
    }
    else {
        # Do not use 'cygpath' - it falsely succeed on paths like '/cygdrive'.
        $cur_dir = `cmd "/c;" echo %__CD__%`;
        if($? != 0 || substr($cur_dir, 0, 1) eq '%') {
            warn "Can't determine Win32 current directory.\n";
            return undef;
        }
        # Remove both '\r' and '\n'.
        $cur_dir =~ s{\n|\r}{}g;

        # Replace back slashes with forward slashes.
        $cur_dir =~ s{\\}{/}g;
    }
    return $cur_dir;
}

#######################################################################
# Returns Win32 current drive letter with colon.
#
sub get_win32_current_drive {
    # Notice parameter "/c;" - it's required to turn off Msys's
    # transformation of '/c' and compatible with Cygwin.
    my $drive_letter = `cmd "/c;" echo %__CD__:~0,2%`;
    if($? != 0 || substr($drive_letter, 1, 1) ne ':') {
        warn "Can't determine current Win32 drive letter.\n";
        return undef;
    }

    return substr($drive_letter, 0, 2);
}

# Internal function. Converts path by using Msys's built-in transformation.
# Returned path may contain duplicated and back slashes.
sub do_msys_transform;

# Internal function. Gets two parameters: first parameter must be single
# drive letter ('c'), second optional parameter is path relative to drive's
# current working directory. Returns Win32 absolute normalized path.
sub get_abs_path_on_win32_drive;

# Internal function. Tries to find or guess Win32 version of given
# absolute Unix-style path. Other types of paths are not supported.
# Returned paths contain only single forward slashes (no back and
# duplicated slashes).
# Last resort. Used only when other transformations are not available.
sub do_dumb_guessed_transform;

#######################################################################
# Converts given path to system native format, i.e. to Win32 format on
# Windows platform. Relative paths converted to relative, absolute
# paths converted to absolute.
#
sub sys_native_path {
    my ($path) = @_;

    # Return untouched on non-Windows platforms.
    return $path if (!os_is_win());

    # Do not process empty path.
    return $path if ($path eq '');

    if($path =~ s{^([a-zA-Z]):$}{\u$1:}) {
        # Path is single drive with colon. (C:)
        # This type of paths is not processed correctly by 'cygpath'.
        # WARNING!
        # Be careful, this relative path can be accidentally transformed
        # into wrong absolute path by adding to it some '/dirname' with
        # slash at font.
        return $path;
    }
    elsif($path =~ m{^\\} || $path =~ m{^[a-zA-Z]:[^/\\]}) {
        # Path is a directory or filename on Win32 current drive or relative
        # path on current directory on specific Win32 drive.
        # ('\path' or 'D:path')
        # First type of paths is not processed by Msys transformation and
        # resolved to absolute path by 'cygpath'.
        # Second type is not processed by Msys transformation and may be
        # incorrectly processed by 'cygpath' (for paths like 'D:..\../.\')

        my $first_char = ucfirst(substr($path, 0, 1));

        # Replace any back and duplicated slashes with single forward slashes.
        $path =~ s{[\\/]+}{/}g;

        # Convert leading slash back to forward slash to indicate
        # directory on Win32 current drive or capitalize drive letter.
        substr($path, 0, 1, $first_char);
        return $path;
    }
    elsif(should_use_cygpath()) {
        # 'cygpath' is available - use it.

        # Remove leading duplicated forward and back slashes, as they may
        # prevent transforming and may be not processed.
        $path =~ s{^([\\/])[\\/]+}{$1}g;

        my $has_final_slash = ($path =~ m{[/\\]$});

        # Use 'cygpath', '-m' means Win32 path with forward slashes.
        chomp($path = `cygpath -m '$path'`);
        if ($? != 0) {
            warn "Can't convert path by \"cygpath\".\n";
            return undef;
        }

        # 'cygpath' may remove last slash for existing directories.
        $path .= '/' if($has_final_slash);

        # Remove any duplicated forward slashes (added by 'cygpath' for root
        # directories)
        $path =~ s{//+}{/}g;

        return $path;
    }
    elsif($^O eq 'msys') {
        # Msys transforms automatically path to Windows native form in staring
        # program parameters if program is not Msys-based.

        $path = do_msys_transform($path);
        return undef if !defined $path;

        # Capitalize drive letter for Win32 paths.
        $path =~ s{^([a-z]:)}{\u$1};

        # Replace any back and duplicated slashes with single forward slashes.
        $path =~ s{[\\/]+}{/}g;
        return $path;
    }
    elsif($path =~ s{^([a-zA-Z]):[/\\]}{\u$1:/}) {
        # Path is already in Win32 form. ('C:\path')

        # Replace any back and duplicated slashes with single forward slashes.
        $path =~ s{[\\/]+}{/}g;
        return $path;
    }
    elsif($path !~ m{^/}) {
        # Path is in relative form. ('path/name', './path' or '../path')

        # Replace any back and duplicated slashes with single forward slashes.
        $path =~ s{[\\/]+}{/}g;
        return $path;
    }

    # OS is Windows, but not Msys, path is absolute, path is not in Win32
    # form and 'cygpath' is not available.
    return do_dumb_guessed_transform($path);
}

#######################################################################
# Converts given path to system native absolute path, i.e. to Win32
# absolute format on Windows platform. Both relative and absolute
# formats are supported for input.
#
sub sys_native_abs_path {
    my ($path) = @_;

    if(!os_is_win()) {
        # Convert path to absolute form.
        $path = Cwd::abs_path($path);

        # Do not process further on non-Windows platforms.
        return $path;
    }

    if($path =~ m{^([a-zA-Z]):($|[^/\\].*$)}) {
        # Path is single drive with colon or relative path on Win32 drive.
        # ('C:' or 'C:path')
        # This kind of relative path is not processed correctly by 'cygpath'.
        # Get specified drive letter
        return get_abs_path_on_win32_drive($1, $2);
    }
    elsif($path eq '') {
        # Path is empty string. Return current directory.
        # Empty string processed correctly by 'cygpath'.

        return sys_native_current_path();
    }
    elsif(should_use_cygpath()) {
        # 'cygpath' is available - use it.

        my $has_final_slash = ($path =~ m{[\\/]$});

        # Remove leading duplicated forward and back slashes, as they may
        # prevent transforming and may be not processed.
        $path =~ s{^([\\/])[\\/]+}{$1}g;

        print "Inter result: \"$path\"\n";
        # Use 'cygpath', '-m' means Win32 path with forward slashes,
        # '-a' means absolute path
        chomp($path = `cygpath -m -a '$path'`);
        if($? != 0) {
            warn "Can't resolve path by usung \"cygpath\".\n";
            return undef;
        }

        # 'cygpath' may remove last slash for existing directories.
        $path .= '/' if($has_final_slash);

        # Remove any duplicated forward slashes (added by 'cygpath' for root
        # directories)
        $path =~ s{//+}{/}g;

        return $path
    }
    elsif($path =~ s{^([a-zA-Z]):[/\\]}{\u$1:/}) {
        # Path is already in Win32 form. ('C:\path')

        # Replace any possible back slashes with forward slashes,
        # remove any duplicated slashes, resolve relative dirs.
        return normalize_path($path);
    }
    elsif(substr($path, 0, 1) eq '\\' ) {
        # Path is directory or filename on Win32 current drive. ('\Windows')

        my $w32drive = get_win32_current_drive();
        return undef if !defined $w32drive;

        # Combine drive and path.
        # Replace any possible back slashes with forward slashes,
        # remove any duplicated slashes, resolve relative dirs.
        return normalize_path($w32drive . $path);
    }

    if(substr($path, 0, 1) ne '/') {
        # Path is in relative form. Resolve relative directories in Unix form
        # *BEFORE* converting to Win32 form otherwise paths like
        # '../../../cygdrive/c/windows' will not be resolved.

        my $cur_dir;
        # MSys shell has built-in command.
        if($^O eq 'msys') {
            $cur_dir = `bash -c 'pwd -L'`;
        }
        else {
            $cur_dir = `pwd -L`;
        }
        if($? != 0) {
            warn "Can't determine current working directory.\n";
            return undef;
        }
        chomp($cur_dir);

        $path = $cur_dir . '/' . $path;
    }

    # Resolve relative dirs.
    $path = normalize_path($path);
    return undef unless defined $path;

    if($^O eq 'msys') {
        # Msys transforms automatically path to Windows native form in staring
        # program parameters if program is not Msys-based.
        $path = do_msys_transform($path);
        return undef if !defined $path;

        # Replace any back and duplicated slashes with single forward slashes.
        $path =~ s{[\\/]+}{/}g;
        return $path;
    }
    # OS is Windows, but not Msys, path is absolute, path is not in Win32
    # form and 'cygpath' is not available.

    return do_dumb_guessed_transform($path);
}

# Internal function. Converts given Unix-style absolute path to Win32 format.
sub simple_transform_win32_to_unix;

#######################################################################
# Converts given path to build system format absolute path, i.e. to
# Msys/Cygwin Unix-style absolute format on Windows platform. Both
# relative and absolute formats are supported for input.
#
sub build_sys_abs_path {
    my ($path) = @_;

    if(!os_is_win()) {
        # Convert path to absolute form.
        $path = Cwd::abs_path($path);

        # Do not process further on non-Windows platforms.
        return $path;
    }

    if($path =~ m{^([a-zA-Z]):($|[^/\\].*$)}) {
        # Path is single drive with colon or relative path on Win32 drive.
        # ('C:' or 'C:path')
        # This kind of relative path is not processed correctly by 'cygpath'.
        # Get specified drive letter

        # Resolve relative dirs in Win32-style path or paths like 'D:/../c/'
        # will be resolved incorrectly.
        # Replace any possible back slashes with forward slashes,
        # remove any duplicated slashes.
        $path = get_abs_path_on_win32_drive($1, $2);
        return undef if !defined $path;

        return simple_transform_win32_to_unix($path);
    }
    elsif($path eq '') {
        # Path is empty string. Return current directory.
        # Empty string processed correctly by 'cygpath'.

        # MSys shell has built-in command.
        if($^O eq 'msys') {
            chomp($path = `bash -c 'pwd -L'`);
        }
        else {
            chomp($path = `pwd -L`);
        }
        if($? != 0) {
            warn "Can't determine Unix-style current working directory.\n";
            return undef;
        }

        # Add final slash if not at root dir.
        $path .= '/' if length($path) > 2;
        return $path;
    }
    elsif(should_use_cygpath()) {
        # 'cygpath' is available - use it.

        my $has_final_slash = ($path =~ m{[\\/]$});

        # Resolve relative directories, as they may be not resolved for
        # Unix-style paths.
        # Remove duplicated slashes, as they may be not processed.
        $path = normalize_path($path);
        return undef if !defined $path;

        # Use 'cygpath', '-u' means Unix-stile path,
        # '-a' means absolute path
        chomp($path = `cygpath -u -a '$path'`);
        if($? != 0) {
            warn "Can't resolve path by usung \"cygpath\".\n";
            return undef;
        }

        # 'cygpath' removes last slash if path is root dir on Win32 drive.
        # Restore it.
        $path .= '/' if($has_final_slash &&
                        substr($path, length($path) - 1, 1) ne '/');

        return $path
    }
    elsif($path =~ m{^[a-zA-Z]:[/\\]}) {
        # Path is already in Win32 form. ('C:\path')

        # Resolve relative dirs in Win32-style path otherwise paths
        # like 'D:/../c/' will be resolved incorrectly.
        # Replace any possible back slashes with forward slashes,
        # remove any duplicated slashes.
        $path = normalize_path($path);
        return undef if !defined $path;

        return simple_transform_win32_to_unix($path);
    }
    elsif(substr($path, 0, 1) eq '\\') {
        # Path is directory or filename on Win32 current drive. ('\Windows')

        my $w32drive = get_win32_current_drive();
        return undef if !defined $w32drive;

        # Combine drive and path.
        # Resolve relative dirs in Win32-style path or paths like 'D:/../c/'
        # will be resolved incorrectly.
        # Replace any possible back slashes with forward slashes,
        # remove any duplicated slashes.
        $path = normalize_path($w32drive . $path);
        return undef if !defined $path;

        return simple_transform_win32_to_unix($path);
    }

    # Path is not in any Win32 form.
    if(substr($path, 0, 1) ne '/') {
        # Path in relative form. Resolve relative directories in Unix form
        # *BEFORE* converting to Win32 form otherwise paths like
        # '../../../cygdrive/c/windows' will not be resolved.

        my $cur_dir;
        # MSys shell has built-in command.
        if($^O eq 'msys') {
            $cur_dir = `bash -c 'pwd -L'`;
        }
        else {
            $cur_dir = `pwd -L`;
        }
        if($? != 0) {
            warn "Can't determine current working directory.\n";
            return undef;
        }
        chomp($cur_dir);

        $path = $cur_dir . '/' . $path;
    }

    return normalize_path($path);
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

    # Check whether path starts from Win32 drive. ('C:path' or 'C:\path')
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

# Internal function. Converts path by using Msys's built-in
# transformation.
sub do_msys_transform {
    my ($path) = @_;
    return undef if $^O ne 'msys';
    return $path if $path eq '';

    # Remove leading double forward slashes, as they turn off Msys
    # transforming.
    $path =~ s{^/[/\\]+}{/};

    # Msys transforms automatically path to Windows native form in staring
    # program parameters if program is not Msys-based.
    # Note: already checked that $path is non-empty.
    $path = `cmd //c echo '$path'`;
    if($? != 0) {
        warn "Can't transform path into Win32 form by using Msys" .
             "internal transformation.\n";
        return undef;
    }

    # Remove double quotes, they are added for paths with spaces,
    # remove both '\r' and '\n'.
    $path =~ s{^\"|\"$|\"\r|\n|\r}{}g;

    return $path;
}

# Internal function. Gets two parameters: first parameter must be single
# drive letter ('c'), second optional parameter is path relative to drive's
# current working directory. Returns Win32 absolute normalized path.
sub get_abs_path_on_win32_drive {
    my ($drv, $rel_path) = @_;
    my $res;

    # Get current directory on specified drive.
    # "/c;" is compatible with both Msys and Cygwin.
    my $cur_dir_on_drv = `cmd "/c;" echo %=$drv:%`;
    if($? != 0) {
        warn "Can't determine Win32 current directory on drive $drv:.\n";
        return undef;
    }

    if($cur_dir_on_drv =~ m{^[%]}) {
        # Current directory on drive is not set, default is
        # root directory.

        $res = ucfirst($drv) . ':/';
    }
    else {
        # Current directory on drive was set.
        # Remove both '\r' and '\n'.
        $cur_dir_on_drv =~ s{\n|\r}{}g;

        # Append relative path part.
        $res = $cur_dir_on_drv . '/';
    }
    $res .= $rel_path if defined $rel_path;

    # Replace any possible back slashes with forward slashes,
    # remove any duplicated slashes, resolve relative dirs.
    return normalize_path($res);
}

# Internal function. Tries to find or guess Win32 version of given
# absolute Unix-style path. Other types of paths are not supported.
# Returned paths contain only single forward slashes (no back and
# duplicated slashes).
# Last resort. Used only when other transformations are not available.
sub do_dumb_guessed_transform {
    my ($path) = @_;

    # Replace any possible back slashes and duplicated forward slashes
    # with single forward slashes.
    $path =~ s{[/\\]+}{/}g;

    # Empty path is not valid.
    return undef if (length($path) == 0);

    # RE to find Win32 drive letter
    my $drv_ltr_re = drives_mounted_on_cygdrive() ?
                        qr{^/cygdrive/([a-zA-Z])($|/.*$)} :
                        qr{^/([a-zA-Z])($|/.*$)};

    # Check path whether path is Win32 directly mapped drive and try to
    # transform it assuming that drive letter is matched to Win32 drive letter.
    if($path =~ m{$drv_ltr_re}) {
        return ucfirst($1) . ':/' if(length($2) == 0);
        return ucfirst($1) . ':' . $2;
    }

    # This may be some custom mapped path. ('/mymount/path')

    # Must check longest possible path component as subdir can be mapped to
    # different directory. For example '/usr/bin/' can be mapped to '/bin/' or
    # '/bin/' can be mapped to '/usr/bin/'.
    my $check_path = $path;
    my $path_tail = '';
    while(1) {
        if(-d $check_path) {
            my $res =
                `(cd "$check_path" && cmd /c "echo %__CD__%") 2>/dev/null`;
            if($? == 0 && substr($path, 0, 1) ne '%') {
                # Remove both '\r' and '\n'.
                $res =~ s{\n|\r}{}g;

                # Replace all back slashes with forward slashes.
                $res =~ s{\\}{/}g;

                if(length($path_tail) > 0) {
                    return $res . $path_tail;
                }
                else {
                    $res =~ s{/$}{} if $check_path !~ m{/$};
                    return $res;
                }
            }
        }
        if($check_path =~ m{(^.*/)([^/]+/*)}) {
            $check_path = $1;
            $path_tail = $2 . $path_tail;
        }
        else {
            # Shouldn't happens as root '/' directory should always
            # be resolvable.
            warn "Can't determine Win32 directory for path \"$path\".\n";
            return undef;
        }
    }
}


# Internal function. Converts given Unix-style absolute path to Win32 format.
sub simple_transform_win32_to_unix {
    my ($path) = @_;

    if(should_use_cygpath()) {
        # 'cygpath' gives precise result.
        my $res;
        chomp($res = `cygpath -a -u '$path'`);
        if($? != 0) {
            warn "Can't determine Unix-style directory for Win32 " .
                 "directory \"$path\".\n";
            return undef;
        }

        # 'cygpath' removes last slash if path is root dir on Win32 drive.
        $res .= '/' if(substr($res, length($res) - 1, 1) ne '/' &&
                       $path =~ m{[/\\]$});
        return $res;
    }

    # 'cygpath' is not available, use guessed transformation.
    if($path !~ s{^([a-zA-Z]):(?:/|\\)}{/\l$1/}) {
        warn "Can't determine Unix-style directory for Win32 " .
             "directory \"$path\".\n";
        return undef;
    }

    $path = '/cygdrive' . $path if(drives_mounted_on_cygdrive());
    return $path;
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
}

1;    # End of module
