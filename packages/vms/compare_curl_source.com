$! Compare_curl_source.com
$!
$! $Id$
$!
$! This procedure compares the files in two directories and reports the
$! differences.  It is customized for the vmsports repository layout.
$!
$! It needs to be customized to the local site directories.
$!
$! This is used by me for these purposes:
$!     1. Compare the original source of a project with an existing
$!        VMS port.
$!     2. Compare the checked out repository of a project with the
$!        the local working copy to make sure they are in sync.
$!     3. Keep a copy directory up to date.  The third is needed by
$!        me because VMS Backup can create a saveset of files from a
$!        NFS mounted volume.
$!
$! First the files in the original source directory which is assumed to be
$! under source code control are compared with the copy directory.
$!
$! Then the files are are only in the copy directory are listed.
$!
$! The result will five diagnostics about of files:
$!    1. Files that are not generation 1.
$!    2. Files missing in the copy directory.
$!    3. Files in the copy directory not in the source directory.
$!    4. Files different from the source directory.
$!    5. Files that VMS DIFF can not process.
$!
$! This needs to be run on an ODS-5 volume.
$!
$! If UPDATE is given as a second parameter, files missing or different in the
$! copy directory will be updated.
$!
$! By default:
$!    The directory src_root:[project_name] will be translated to something like
$!    DISK:[dir.dir.reference.project_name] and this will be used
$!    to calculate DISK:[dir.dir.vms_source.project_name] for the VMS specific
$!    source directory.
$!
$!    The copy directory is vms_root:[project_name]
$!    The UPDATE parameter is ignored.
$!
$!    This setting is used to make sure that the working vms directory
$!    and the repository checkout directory have the same contents.
$!
$! If P1 is "SRCBCK" then this
$!     The source directory tree is: src_root:[project_name]
$!     The copy directory is src_root1:[project_name]
$!
$!   src_root1:[project_name] is used by me to work around that VMS backup will
$!   not use NFS as a source directory so I need to make a copy.
$!
$!   This is to make sure that the backup save set for the unmodified
$!   source is up to date.
$!
$!   If your repository checkout is not on an NFS mounted volume, you do not
$!   need to use this option or have the logical name src_root1 defined.
$!
$! If P1 is "VMSBCK" then this changes the two directories:
$!    The source directory is vms_root:[project_name]
$!    The copy directory is vms_root1:[project_name]
$!
$!   vms_root:[project_name] is where I do the VMS specific edits.
$!   vms_root1:[project_name] is used by me to work around that VMS backup will
$!   not use NFS as a source directory so I need to make a copy.
$!
$!   This is to make sure that the backup save set for the unmodified
$!   source is up to date.
$!
$! Copyright 2011, John Malmberg
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
$! 18-Aug-2011  J. Malmberg
$!==========================================================================
$!
$! Update missing/changed files.
$ update_file = 0
$ if (p2 .eqs. "UPDATE")
$ then
$   update_file = 1
$ endif
$!
$ myproc = f$environment("PROCEDURE")
$ myprocdir = f$parse(myproc,,,"DIRECTORY") - "[" - "]" - "<" - ">"
$ myprocdir = f$edit(myprocdir, "LOWERCASE")
$ mydefault = f$environment("DEFAULT")
$ mydir = f$parse(mydefault,,,"DIRECTORY")
$ mydir = f$edit(mydir, "LOWERCASE")
$ odelim = f$extract(0, 1, mydir)
$ mydir = mydir - "[" - "]" - "<" - ">"
$ mydev = f$parse(mydefault,,,"DEVICE")
$!
$ ref = ""
$ if P1 .eqs. ""
$ then
$   ref_base_dir = myprocdir
$   wrk_base_dir = mydir
$   update_file = 0
$   resultd = f$parse("src_root:",,,,"NO_CONCEAL")
$   resultd = f$edit(resultd, "LOWERCASE")
$   resultd = resultd - "][" - "><" - ".;" - ".."
$   resultd_len = f$length(resultd) - 1
$   delim = f$extract(resultd_len, 1, resultd)
$   ref_root_base = mydir + delim
$   resultd = resultd - ref_root_base - "reference." + "vms_source."
$   ref = resultd + ref_base_dir
$   wrk = "VMS_ROOT:" + odelim + wrk_base_dir
$   resultd_len = f$length(resultd) - 1
$   resultd = f$extract(0, resultd_len, resultd) + delim
$   ref_root_dir = f$parse(resultd,,,"DIRECTORY")
$   ref_root_dir = f$edit(ref_root_dir, "LOWERCASE")
$   ref_root_dir = ref_root_dir - "[" - "]"
$   ref_base_dir = ref_root_dir + "." + ref_base_dir
$ endif
$!
$ if p1 .eqs. "SRCBCK"
$ then
$   ref_base_dir = "curl"
$   wrk_base_dir = "curl"
$   ref = "src_root:[" + ref_base_dir
$   wrk = "src_root1:[" + wrk_base_dir
$   if update_file
$   then
$       if f$search("src_root1:[000000]curl.dir") .eqs. ""
$       then
$           create/dir/prot=o:rwed src_root1:[curl]
$       endif
$   endif
$ endif
$!
$!
$ if p1 .eqs. "VMSBCK"
$ then
$   ref_base_dir = "curl"
$   wrk_base_dir = "curl"
$   ref = "vms_root:[" + ref_base_dir
$   wrk = "vms_root1:[" + wrk_base_dir
$   if update_file
$   then
$       if f$search("vms_root1:[000000]curl.dir") .eqs. ""
$       then
$           create/dir/prot=o:rwed vms_root1:[curl]
$       endif
$   endif
$ endif
$!
$!
$ if ref .eqs. ""
$ then
$   write sys$output "Unknown compare type specified!"
$   exit 44
$ endif
$!
$!
$! Future - check the device types involved for the
$! the syntax to check.
$ ODS2_SYNTAX = 0
$ NFS_MANGLE = 0
$ PWRK_MANGLE = 0
$!
$ vax = f$getsyi("HW_MODEL") .lt. 1024
$ if vax
$ then
$   ODS2_SYNTAX = 1
$ endif
$!
$ report_missing = 1
$!
$ if .not. ODS2_SYNTAX
$ then
$   set proc/parse=extended
$ endif
$!
$loop:
$   ref_spec = f$search("''ref'...]*.*;",1)
$   if ref_spec .eqs. "" then goto loop_end
$!
$   ref_dev = f$parse(ref_spec,,,"DEVICE")
$   ref_dir = f$parse(ref_spec,,,"DIRECTORY")
$   ref_dir = f$edit(ref_dir, "LOWERCASE")
$   ref_name = f$parse(ref_spec,,,"NAME")
$   ref_type = f$parse(ref_spec,,,"TYPE")
$!
$!
$   rel_path = ref_dir - "[" - ref_base_dir
$!  rel_path_len = f$length(rel_path) - 1
$!  delim = f$extract(rel_path_len, 1, rel_path)
$!  rel_path = rel_path - ".]" - ".>" - "]" - ">"
$!  rel_path = rel_path + delim
$!
$   if ODS2_SYNTAX
$   then
$!       if rel_path .eqs. ".examples.scripts^.noah]"
$!       then
$!           rel_path = ".examples.scripts_noah]"
$!       endif
$!       if rel_path .eqs. ".examples.scripts^.v2]"
$!       then
$!           rel_path = ".examples.scripts_v2]"
$!       endif
$   endif
$!
$   wrk_path = wrk + rel_path
$!
$   ref_name_type = ref_name + ref_type
$!
$   if ODS2_SYNTAX
$   then
$   endif
$!
$   wrk_spec = wrk_path + ref_name_type
$!
$!
$   wrk_chk = f$search(wrk_spec, 0)
$   if wrk_chk .eqs. ""
$   then
$       if report_missing
$       then
$           write sys$output "''wrk_spec' is missing"
$        endif
$        if update_file
$        then
$            copy/log 'ref_spec' 'wrk_spec'
$        endif
$        goto loop
$   endif
$!
$   wrk_name = f$parse(wrk_spec,,,"NAME")
$   wrk_type = f$parse(wrk_spec,,,"TYPE")
$   wrk_fname = wrk_name + wrk_type"
$   ref_fname = ref_name + ref_type
$!
$   if ref_fname .nes. wrk_fname
$   then
$       write sys$output "''wrk_spc' wrong name, should be ""''ref_fname'"""
$   endif
$!
$   ref_type = f$edit(ref_type, "UPCASE")
$   if ref_type .eqs. ".DIR" then goto loop
$!
$   if ODS2_SYNTAX
$   then
$       ref_fname = f$edit(ref_fname, "LOWERCASE")
$   endif
$!
$!  These files are in the wrong format for VMS diff, and we don't change them.
$   ref_skip = 0
$   if ref_type .eqs. ".PDF" then ref_skip = 1
$   if ref_type .eqs. ".HTML" then ref_skip = 1
$   if ref_type .eqs. ".HQX" then ref_skip = 1
$   if ref_type .eqs. ".P12" then ref_skip = 1
$   if ref_type .eqs. "."
$   then
$       if f$locate("test", ref_fname) .eq. 0 then ref_skip = 1
$       if ref_fname .eqs. "configure." then ref_skip = 1
$   endif
$   if ref_fname .eqs. "MACINSTALL.TXT" then ref_skip = 1
$   if ref_fname .eqs. "$macinstall.txt" then ref_skip = 1
$   if ref_fname .eqs. "curl.mcp$5nxml$5nsit$5nhqx" then ref_skip = 1
$   if ref_fname .eqs. "curl_GUSIConfig.cpp" then ref_skip = 1
$   if ref_fname .eqs. "curl_$gusic$onfig.cpp" then ref_skip = 1
$   if ref_fname .eqs. "macos_main.cpp" then ref_skip = 1
$!
$!
$   if ref_skip .ne. 0
$   then
$      if report_missing
$      then
$          write sys$output "Skipping diff of ''ref_fname'"
$      endif
$      goto loop
$   endif
$!
$!
$   wrk_ver = f$parse(wrk_chk,,,"VERSION")
$   if wrk_ver .nes. ";1"
$   then
$       write sys$output "Version for ''wrk_spec' is not 1"
$   endif
$   set noon
$   diff/out=nl: 'wrk_spec' 'ref_spec'
$   if $severity .nes. "1"
$   then
$       write sys$output "''wrk_spec' is different from ''ref_spec'"
$       if update_file
$       then
$           delete 'wrk_spec';*
$           copy/log 'ref_spec' 'wrk_spec'
$       endif
$   endif
$   set on
$
$!
$   goto loop
$loop_end:
$!
$!
$missing_loop:
$!  For missing loop, check the latest generation.
$   ref_spec = f$search("''wrk'...]*.*;")
$   if ref_spec .eqs. "" then goto missing_loop_end
$!
$   ref_dev = f$parse(ref_spec,,,"DEVICE")
$   ref_dir = f$parse(ref_spec,,,"DIRECTORY")
$   ref_dir = f$edit(ref_dir, "LOWERCASE")
$   ref_name = f$parse(ref_spec,,,"NAME")
$   ref_type = f$parse(ref_spec,,,"TYPE")
$   ref_name_type = ref_name + ref_type
$!
$   rel_path = ref_dir - "[" - wrk_base_dir
$!
$!
$   wrk_path = ref + rel_path
$   wrk_spec = wrk_path + ref_name + ref_type
$   wrk_name = f$parse(wrk_spec,,,"NAME")
$   wrk_type = f$parse(wrk_spec,,,"TYPE")
$!
$   wrk_fname = wrk_name + wrk_type"
$   ref_fname = ref_name + ref_type
$!
$   wrk_skip = 0
$   ref_utype = f$edit(ref_type,"UPCASE")
$   ref_ufname = f$edit(ref_fname,"UPCASE")
$!
$   if wrk_skip .eq. 0
$   then
$       wrk_chk = f$search(wrk_spec, 0)
$       if wrk_chk .eqs. ""
$       then
$           if report_missing
$           then
$               write sys$output "''wrk_spec' is missing"
$           endif
$           goto missing_loop
$       endif
$   else
$       goto missing_loop
$   endif
$!
$   if ref_fname .nes. wrk_fname
$   then
$       write sys$output "''wrk_spc' wrong name, should be ""''ref_fname'"""
$   endif
$!
$   if ref_utype .eqs. ".DIR" then goto missing_loop
$!
$   wrk_ver = f$parse(wrk_chk,,,"VERSION")
$   if wrk_ver .nes. ";1"
$   then
$      write sys$output "Version for ''wrk_spec' is not 1"
$   endif
$!
$   goto missing_loop
$!
$!
$missing_loop_end:
$!
$exit
