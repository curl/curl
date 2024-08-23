/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at https://curl.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 * SPDX-License-Identifier: curl
 *
 ***************************************************************************/
/* File: curl_crtl_init.c
 *
 * This file makes sure that the DECC Unix settings are correct for
 * the mode the program is run in.
 *
 * The CRTL has not been initialized at the time that these routines
 * are called, so many routines can not be called.
 *
 * This is a module that provides a LIB$INITIALIZE routine that
 * will turn on some CRTL features that are not enabled by default.
 *
 * The CRTL features can also be turned on via logical names, but that
 * impacts all programs and some aren't ready, willing, or able to handle
 * those settings.
 *
 * On VMS versions that are too old to use the feature setting API, this
 * module falls back to using logical names.
 *
 * Copyright (C) John Malmberg
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT
 * OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 */

/* Unix headers */
#include <stdio.h>
#include <string.h>

/* VMS specific headers */
#include <descrip.h>
#include <lnmdef.h>
#include <stsdef.h>

#pragma member_alignment save
#pragma nomember_alignment longword
#pragma message save
#pragma message disable misalgndmem
struct itmlst_3 {
  unsigned short int buflen;
  unsigned short int itmcode;
  void *bufadr;
  unsigned short int *retlen;
};
#pragma message restore
#pragma member_alignment restore

#ifdef __VAX
#define ENABLE "ENABLE"
#define DISABLE "DISABLE"
#else

#define ENABLE TRUE
#define DISABLE 0
int   decc$feature_get_index (const char *name);
int   decc$feature_set_value (int index, int mode, int value);
#endif

int   SYS$TRNLNM(
    const unsigned long *attr,
    const struct dsc$descriptor_s *table_dsc,
    struct dsc$descriptor_s *name_dsc,
    const unsigned char *acmode,
    const struct itmlst_3 *item_list);
int   SYS$CRELNM(
    const unsigned long *attr,
    const struct dsc$descriptor_s *table_dsc,
    const struct dsc$descriptor_s *name_dsc,
    const unsigned char *acmode,
    const struct itmlst_3 *item_list);


/* Take all the fun out of simply looking up a logical name */
static int sys_trnlnm(const char *logname,
                      char *value,
                      int value_len)
{
  const $DESCRIPTOR(table_dsc, "LNM$FILE_DEV");
  const unsigned long attr = LNM$M_CASE_BLIND;
  struct dsc$descriptor_s name_dsc;
  int status;
  unsigned short result;
  struct itmlst_3 itlst[2];

  itlst[0].buflen = value_len;
  itlst[0].itmcode = LNM$_STRING;
  itlst[0].bufadr = value;
  itlst[0].retlen = &result;

  itlst[1].buflen = 0;
  itlst[1].itmcode = 0;

  name_dsc.dsc$w_length = strlen(logname);
  name_dsc.dsc$a_pointer = (char *)logname;
  name_dsc.dsc$b_dtype = DSC$K_DTYPE_T;
  name_dsc.dsc$b_class = DSC$K_CLASS_S;

  status = SYS$TRNLNM(&attr, &table_dsc, &name_dsc, 0, itlst);

  if($VMS_STATUS_SUCCESS(status)) {

    /* Null terminate and return the string */
    /*--------------------------------------*/
    value[result] = '\0';
  }

  return status;
}

/* How to simply create a logical name */
static int sys_crelnm(const char *logname,
                      const char *value)
{
  int ret_val;
  const char *proc_table = "LNM$PROCESS_TABLE";
  struct dsc$descriptor_s proc_table_dsc;
  struct dsc$descriptor_s logname_dsc;
  struct itmlst_3 item_list[2];

  proc_table_dsc.dsc$a_pointer = (char *) proc_table;
  proc_table_dsc.dsc$w_length = strlen(proc_table);
  proc_table_dsc.dsc$b_dtype = DSC$K_DTYPE_T;
  proc_table_dsc.dsc$b_class = DSC$K_CLASS_S;

  logname_dsc.dsc$a_pointer = (char *) logname;
  logname_dsc.dsc$w_length = strlen(logname);
  logname_dsc.dsc$b_dtype = DSC$K_DTYPE_T;
  logname_dsc.dsc$b_class = DSC$K_CLASS_S;

  item_list[0].buflen = strlen(value);
  item_list[0].itmcode = LNM$_STRING;
  item_list[0].bufadr = (char *)value;
  item_list[0].retlen = NULL;

  item_list[1].buflen = 0;
  item_list[1].itmcode = 0;

  ret_val = SYS$CRELNM(NULL, &proc_table_dsc, &logname_dsc, NULL, item_list);

  return ret_val;
}


 /* Start of DECC RTL Feature handling */

/*
** Sets default value for a feature
*/
#ifdef __VAX
static void set_feature_default(const char *name, const char *value)
{
  sys_crelnm(name, value);
}
#else
static void set_feature_default(const char *name, int value)
{
  int index;

  index = decc$feature_get_index(name);

  if(index > 0)
    decc$feature_set_value (index, 0, value);
}
#endif

static void set_features(void)
{
  int status;
  char unix_shell_name[255];
  int use_unix_settings = 1;

  status = sys_trnlnm("GNV$UNIX_SHELL",
                      unix_shell_name, sizeof(unix_shell_name) -1);
  if(!$VMS_STATUS_SUCCESS(status)) {
    use_unix_settings = 0;
  }

  /* ACCESS should check ACLs or it is lying. */
  set_feature_default("DECC$ACL_ACCESS_CHECK", ENABLE);

  /* We always want the new parse style */
  set_feature_default("DECC$ARGV_PARSE_STYLE", ENABLE);


  /* Unless we are in POSIX compliant mode, we want the old POSIX root
   * enabled.
   */
  set_feature_default("DECC$DISABLE_POSIX_ROOT", DISABLE);

  /* EFS charset, means UTF-8 support */
  /* VTF-7 support is controlled by a feature setting called UTF8 */
  set_feature_default("DECC$EFS_CHARSET", ENABLE);
  set_feature_default("DECC$EFS_CASE_PRESERVE", ENABLE);

  /* Support timestamps when available */
  set_feature_default("DECC$EFS_FILE_TIMESTAMPS", ENABLE);

  /* Cache environment variables - performance improvements */
  set_feature_default("DECC$ENABLE_GETENV_CACHE", ENABLE);

  /* Start out with new file attribute inheritance */
#ifdef __VAX
  set_feature_default("DECC$EXEC_FILEATTR_INHERITANCE", "2");
#else
  set_feature_default("DECC$EXEC_FILEATTR_INHERITANCE", 2);
#endif

  /* Don't display trailing dot after files without type */
  set_feature_default("DECC$READDIR_DROPDOTNOTYPE", ENABLE);

  /* For standard output channels buffer output until terminator */
  /* Gets rid of output logs with single character lines in them. */
  set_feature_default("DECC$STDIO_CTX_EOL", ENABLE);

  /* Fix mv aa.bb aa  */
  set_feature_default("DECC$RENAME_NO_INHERIT", ENABLE);

  if(use_unix_settings) {

    /* POSIX requires that open files be able to be removed */
    set_feature_default("DECC$ALLOW_REMOVE_OPEN_FILES", ENABLE);

    /* Default to outputting Unix filenames in VMS routines */
    set_feature_default("DECC$FILENAME_UNIX_ONLY", ENABLE);
    /* FILENAME_UNIX_ONLY Implicitly sets */
    /* decc$disable_to_vms_logname_translation */

    set_feature_default("DECC$FILE_PERMISSION_UNIX", ENABLE);

    set_feature_default("DECC$FILE_SHARING", ENABLE);

    set_feature_default("DECC$FILE_OWNER_UNIX", ENABLE);
    set_feature_default("DECC$POSIX_SEEK_STREAM_FILE", ENABLE);

  }
  else {
    set_feature_default("DECC$FILENAME_UNIX_REPORT", ENABLE);
  }

  /* When reporting Unix filenames, glob the same way */
  set_feature_default("DECC$GLOB_UNIX_STYLE", ENABLE);

  /* The VMS version numbers on Unix filenames is incompatible with most */
  /* ported packages. */
  set_feature_default("DECC$FILENAME_UNIX_NO_VERSION", ENABLE);

  /* The VMS version numbers on Unix filenames is incompatible with most */
  /* ported packages. */
  set_feature_default("DECC$UNIX_PATH_BEFORE_LOGNAME", ENABLE);

  /* Set strtol to proper behavior */
  set_feature_default("DECC$STRTOL_ERANGE", ENABLE);

  /* Commented here to prevent future bugs:  A program or user should */
  /* never ever enable DECC$POSIX_STYLE_UID. */
  /* It will probably break all code that accesses UIDs */
  /*  do_not_set_default ("DECC$POSIX_STYLE_UID", TRUE); */
}


/* Some boilerplate to force this to be a proper LIB$INITIALIZE section */

#pragma nostandard
#pragma extern_model save
#ifdef __VAX
#pragma extern_model strict_refdef "LIB$INITIALIZE" nowrt, long, nopic
#else
#pragma extern_model strict_refdef "LIB$INITIALIZE" nowrt, long
#    if __INITIAL_POINTER_SIZE
#        pragma __pointer_size __save
#        pragma __pointer_size 32
#    else
#        pragma __required_pointer_size __save
#        pragma __required_pointer_size 32
#    endif
#endif
/* Set our contribution to the LIB$INITIALIZE array */
void (* const iniarray[])(void) = {set_features };
#ifndef __VAX
#    if __INITIAL_POINTER_SIZE
#        pragma __pointer_size __restore
#    else
#        pragma __required_pointer_size __restore
#    endif
#endif


/*
** Force a reference to LIB$INITIALIZE to ensure it
** exists in the image.
*/
int LIB$INITIALIZE(void);
#ifdef __DECC
#pragma extern_model strict_refdef
#endif
    int lib_init_ref = (int) LIB$INITIALIZE;
#ifdef __DECC
#pragma extern_model restore
#pragma standard
#endif
