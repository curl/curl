$! File: stage_curl_install.com
$!
$! $Id$
$!
$! This updates or removes the GNV$CURL.EXE and related files for the
$! new_gnu:[*...] directory tree for running the self tests.
$!
$! The files installed/removed are:
$!     [usr.bin]gnv$curl.exe
$!     [usr.bin]curl-config.
$!     [usr.lib]gnv$libcurl.exe
$!     [usr.bin]curl. hard link for [usr.bin]gnv$curl.exe
$!     [usr.include.curl]curl.h
$!     [usr.include.curl]curlver.h
$!     [usr.include.curl]easy.h
$!     [usr.include.curl]mprintf.h
$!     [usr.include.curl]multi.h
$!     [usr.include.curl]stdcheaders.h
$!     [usr.include.curl]typecheck-gcc.h
$!     [usr.lib.pkgconfig]libcurl.pc
$!     [usr.share.man.man1]curl-config.1
$!     [usr.share.man.man1]curl.1
$!     [usr.share.man.man3]curl*.3
$!     [usr.share.man.man3]libcurl*.3
$! Future: A symbolic link to the release notes?
$!
$! Copyright 2012, John Malmberg
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
$!
$! 20-Aug-2012  J. Malmberg
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
$! If we are staging files, make sure that the libcurl.pc and curl-config
$! files are present.
$ if remove_files .eq. 0
$ then
$   if f$search("[--]libcurl.pc") .eqs. ""
$   then
$       @build_libcurl_pc.com
$   endif
$   if f$search("[--]curl-config") .eqs. ""
$   then
$       @build_curl-config_script.com
$   endif
$ endif
$!
$!
$! Dest dirs
$!------------------
$ dest_dirs1 = "[usr],[usr.bin],[usr.include],[usr.include.curl]"
$ dest_dirs2 = ",[usr.bin],[usr.lib.pkgconfig],[usr.share]"
$ dest_dirs3 = ",[usr.share.man],[usr.share.man.man1],[usr.share.man.man3]"
$ dest_dirs = dest_dirs1 + dest_dirs2 + dest_dirs3
$!
$!
$!   Alias links needed.
$!-------------------------
$ source_curl = "gnv$curl.exe"
$ dest_curl = "[bin]gnv$curl.exe"
$ curl_links = "[bin]curl."
$ new_gnu = "new_gnu:"
$!
$!
$! Create the directories if they do not exist
$!---------------------------------------------
$ i = 0
$curl_dir_loop:
$   this_dir = f$element(i, ",", dest_dirs)
$   i = i + 1
$   if this_dir .eqs. "" then goto curl_dir_loop
$   if this_dir .eqs. "," then goto curl_dir_loop_end
$!  Just create the directories, do not delete them.
$!  --------------------------------------------------
$   if remove_files .eq. 0
$   then
$       create/dir 'new_gnu''this_dir'/prot=(o:rwed)
$   endif
$   goto curl_dir_loop
$curl_dir_loop_end:
$!
$!
$! Need to add in the executable file
$!-----------------------------------
$ if remove_files .eq. 0
$ then
$   copy [--.src]curl.exe 'new_gnu'[usr.bin]gnv$curl.exe/prot=w:re
$   copy [--]curl-config. 'new_gnu'[usr.bin]curl-config./prot=w:re
$   copy sys$disk:[]gnv$libcurl.exe 'new_gnu'[usr.lib]gnv$libcurl.exe/prot=w:re
$ endif
$!
$ if remove_files .eq. 0
$ then
$   set file/enter='new_gnu'[bin]curl. 'new_gnu'[usr.bin]gnv$curl.exe
$ else
$   file = "''new_gnu'[bin]curl."
$   if f$search(file) .nes. "" then set file/remove 'file';*
$ endif
$!
$!
$ if remove_files .eq. 0
$ then
$   copy [--.include.curl]curl.h 'new_gnu'[usr.include.curl]curl.h
$   copy [--.include.curl]system.h -
         'new_gnu'[usr.include.curl]system.h
$   copy [--.include.curl]curlver.h -
         'new_gnu'[usr.include.curl]curlver.h
$   copy [--.include.curl]easy.h -
         'new_gnu'[usr.include.curl]easy.h
$   copy [--.include.curl]mprintf.h -
         'new_gnu'[usr.include.curl]mprintf.h
$   copy [--.include.curl]multi.h -
         'new_gnu'[usr.include.curl]multi.h
$   copy [--.include.curl]stdcheaders.h -
         'new_gnu'[usr.include.curl]stdcheaders.h
$   copy [--.include.curl]typecheck-gcc.h -
         'new_gnu'[usr.include.curl]typecheck-gcc.h
$   copy [--]libcurl.pc 'new_gnu'[usr.lib.pkgconfig]libcurl.pc
$!
$   copy [--.docs]curl-config.1 'new_gnu'[usr.share.man.man1]curl-config.1
$   copy [--.docs]curl.1 'new_gnu'[usr.share.man.man1]curl.1
$!
$   copy [--.docs.libcurl]*.3 -
         'new_gnu'[usr.share.man.man3]*.3
$!
$ else
$   file = "''new_gnu'[usr.bin]curl-config."
$   if f$search(file) .nes. "" then delete 'file';*
$   file = "''new_gnu'[usr.bin]gnv$curl.exe"
$   if f$search(file) .nes. "" then delete 'file';*
$   file = "''new_gnu'[usr.lib]gnv$libcurl.exe"
$   if f$search(file) .nes. "" then delete 'file';*
$   file = "''new_gnu'[usr.include.curl]*.h"
$   if f$search(file) .nes. "" then delete 'file';*
$   file = "''new_gnu'[usr.share.man.man1]curl-config.1"
$   if f$search(file) .nes. "" then delete 'file';*
$   file = "''new_gnu'[usr.share.man.man1]curl.1"
$   if f$search(file) .nes. "" then delete 'file';*
$   file = "''new_gnu'[usr.share.man.man3]curl*.3"
$   if f$search(file) .nes. "" then delete 'file';*
$   file = "''new_gnu'[usr.share.man.man3]libcurl*.3"
$   if f$search(file) .nes. "" then delete 'file';*
$ endif
$!
