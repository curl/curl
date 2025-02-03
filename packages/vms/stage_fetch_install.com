$! File: stage_fetch_install.com
$!
$! This updates or removes the GNV$FETCH.EXE and related files for the
$! new_gnu:[*...] directory tree for running the self tests.
$!
$! The files installed/removed are:
$!     [usr.bin]gnv$fetch.exe
$!     [usr.bin]fetch-config.
$!     [usr.lib]gnv$libfetch.exe
$!     [usr.bin]fetch. hard link for [usr.bin]gnv$fetch.exe
$!     [usr.include.fetch]fetch.h
$!     [usr.include.fetch]fetchver.h
$!     [usr.include.fetch]easy.h
$!     [usr.include.fetch]mprintf.h
$!     [usr.include.fetch]multi.h
$!     [usr.include.fetch]stdcheaders.h
$!     [usr.include.fetch]typecheck-gcc.h
$!     [usr.lib.pkgconfig]libfetch.pc
$!     [usr.share.man.man1]fetch-config.1
$!     [usr.share.man.man1]fetch.1
$!     [usr.share.man.man3]fetch*.3
$!     [usr.share.man.man3]libfetch*.3
$! Future: A symbolic link to the release notes?
$!
$! Copyright (C) John Malmberg
$!
$! Permission to use, copy, modify, and/or distribute this software for any
$! purpose with or without fee is hereby granted, provided that the above
$! copyright notice and this permission notice appear in all copies.
$!
$! THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
$! WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
$! MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
$! ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
$! WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
$! ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT
$! OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
$!
$! SPDX-License-Identifier: ISC
$!
$!===========================================================================
$!
$ arch_type = f$getsyi("ARCH_NAME")
$ arch_code = f$extract(0, 1, arch_type)
$!
$ if arch_code .nes. "V"
$ then
$   set proc/parse=extended
$ endif
$!
$!
$! If the first parameter begins with "r" or "R" then this is to
$! remove the files instead of installing them.
$ remove_filesq = f$edit(p1, "upcase,trim")
$ remove_filesq = f$extract(0, 1, remove_filesq)
$ remove_files = 0
$ if remove_filesq .eqs. "R" then remove_files = 1
$!
$!
$! If we are staging files, make sure that the libfetch.pc and fetch-config
$! files are present.
$ if remove_files .eq. 0
$ then
$   if f$search("[--]libfetch.pc") .eqs. ""
$   then
$       @build_libfetch_pc.com
$   endif
$   if f$search("[--]fetch-config") .eqs. ""
$   then
$       @build_fetch-config_script.com
$   endif
$ endif
$!
$!
$! Dest dirs
$!------------------
$ dest_dirs1 = "[usr],[usr.bin],[usr.include],[usr.include.fetch]"
$ dest_dirs2 = ",[usr.bin],[usr.lib.pkgconfig],[usr.share]"
$ dest_dirs3 = ",[usr.share.man],[usr.share.man.man1],[usr.share.man.man3]"
$ dest_dirs = dest_dirs1 + dest_dirs2 + dest_dirs3
$!
$!
$!   Alias links needed.
$!-------------------------
$ source_fetch = "gnv$fetch.exe"
$ dest_fetch = "[bin]gnv$fetch.exe"
$ fetch_links = "[bin]fetch."
$ new_gnu = "new_gnu:"
$!
$!
$! Create the directories if they do not exist
$!---------------------------------------------
$ i = 0
$fetch_dir_loop:
$   this_dir = f$element(i, ",", dest_dirs)
$   i = i + 1
$   if this_dir .eqs. "" then goto fetch_dir_loop
$   if this_dir .eqs. "," then goto fetch_dir_loop_end
$!  Just create the directories, do not delete them.
$!  --------------------------------------------------
$   if remove_files .eq. 0
$   then
$       create/dir 'new_gnu''this_dir'/prot=(o:rwed)
$   endif
$   goto fetch_dir_loop
$fetch_dir_loop_end:
$!
$!
$! Need to add in the executable file
$!-----------------------------------
$ if remove_files .eq. 0
$ then
$   copy [--.src]fetch.exe 'new_gnu'[usr.bin]gnv$fetch.exe/prot=w:re
$   copy [--]fetch-config. 'new_gnu'[usr.bin]fetch-config./prot=w:re
$   copy sys$disk:[]gnv$libfetch.exe 'new_gnu'[usr.lib]gnv$libfetch.exe/prot=w:re
$ endif
$!
$ if remove_files .eq. 0
$ then
$   set file/enter='new_gnu'[bin]fetch. 'new_gnu'[usr.bin]gnv$fetch.exe
$ else
$   file = "''new_gnu'[bin]fetch."
$   if f$search(file) .nes. "" then set file/remove 'file';*
$ endif
$!
$!
$ if remove_files .eq. 0
$ then
$   copy [--.include.fetch]fetch.h 'new_gnu'[usr.include.fetch]fetch.h
$   copy [--.include.fetch]system.h -
         'new_gnu'[usr.include.fetch]system.h
$   copy [--.include.fetch]fetchver.h -
         'new_gnu'[usr.include.fetch]fetchver.h
$   copy [--.include.fetch]easy.h -
         'new_gnu'[usr.include.fetch]easy.h
$   copy [--.include.fetch]mprintf.h -
         'new_gnu'[usr.include.fetch]mprintf.h
$   copy [--.include.fetch]multi.h -
         'new_gnu'[usr.include.fetch]multi.h
$   copy [--.include.fetch]stdcheaders.h -
         'new_gnu'[usr.include.fetch]stdcheaders.h
$   copy [--.include.fetch]typecheck-gcc.h -
         'new_gnu'[usr.include.fetch]typecheck-gcc.h
$   copy [--]libfetch.pc 'new_gnu'[usr.lib.pkgconfig]libfetch.pc
$!
$   copy [--.docs]fetch-config.1 'new_gnu'[usr.share.man.man1]fetch-config.1
$   copy [--.docs]fetch.1 'new_gnu'[usr.share.man.man1]fetch.1
$!
$   copy [--.docs.libfetch]*.3 -
         'new_gnu'[usr.share.man.man3]*.3
$!
$ else
$   file = "''new_gnu'[usr.bin]fetch-config."
$   if f$search(file) .nes. "" then delete 'file';*
$   file = "''new_gnu'[usr.bin]gnv$fetch.exe"
$   if f$search(file) .nes. "" then delete 'file';*
$   file = "''new_gnu'[usr.lib]gnv$libfetch.exe"
$   if f$search(file) .nes. "" then delete 'file';*
$   file = "''new_gnu'[usr.include.fetch]*.h"
$   if f$search(file) .nes. "" then delete 'file';*
$   file = "''new_gnu'[usr.share.man.man1]fetch-config.1"
$   if f$search(file) .nes. "" then delete 'file';*
$   file = "''new_gnu'[usr.share.man.man1]fetch.1"
$   if f$search(file) .nes. "" then delete 'file';*
$   file = "''new_gnu'[usr.share.man.man3]fetch*.3"
$   if f$search(file) .nes. "" then delete 'file';*
$   file = "''new_gnu'[usr.share.man.man3]libfetch*.3"
$   if f$search(file) .nes. "" then delete 'file';*
$ endif
$!
