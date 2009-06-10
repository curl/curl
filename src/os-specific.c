/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2009, Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at http://curl.haxx.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 * $Id$
 ***************************************************************************/
#include "setup.h"

#include <curl/curl.h>

#define ENABLE_CURLX_PRINTF
#include "curlx.h"

#include "os-specific.h"

#if defined(CURLDEBUG) && defined(CURLTOOLDEBUG)
#  include "memdebug.h"
#endif

#ifdef __VMS

#include "curlmsg_vms.h"

void decc$__posix_exit(int __status);
void decc$exit(int __status);

static int vms_shell = -1;

/* VMS has a DCL shell and and also has Unix shells ported to it.
 * When curl is running under a Unix shell, we want it to be as much
 * like Unix as possible.
 */
int is_vms_shell(void)
{
  char *shell;

  /* Have we checked the shell yet? */
  if(vms_shell >= 0)
    return vms_shell;

  shell = getenv("SHELL");

  /* No shell, means DCL */
  if(shell == NULL) {
    vms_shell = 1;
    return 1;
  }

  /* Have to make sure some one did not set shell to DCL */
  if(strcmp(shell, "DCL") == 0) {
    vms_shell = 1;
    return 1;
  }

  vms_shell = 0;
  return 0;
}

/*
 * VMS has two exit() routines.  When running under a Unix style shell, then
 * Unix style and the __posix_exit() routine is used.
 *
 * When running under the DCL shell, then the VMS encoded codes and decc$exit()
 * is used.
 *
 * We can not use exit() or return a code from main() because the actual
 * routine called depends on both the compiler version, compile options, and
 * feature macro settings, and one of the exit routines is hidden at compile
 * time.
 *
 * Since we want Curl to work properly under the VMS DCL shell and Unix
 * shells under VMS, this routine should compile correctly regardless of
 * the settings.
 */

void vms_special_exit(int code, int vms_show)
{
  int vms_code;

  /* The Posix exit mode is only available after VMS 7.0 */
#if __CRTL_VER >= 70000000
  if(is_vms_shell() == 0) {
    decc$__posix_exit(code);
  }
#endif

  if(code > CURL_LAST) {   /* If CURL_LAST exceeded then */
    vms_code = CURL_LAST;  /* curlmsg.h is out of sync.  */
  }
  else {
    vms_code = vms_cond[code] | vms_show;
  }
  decc$exit(vms_code);
}

#endif /* __VMS */

