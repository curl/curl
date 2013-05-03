/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2013, Daniel Stenberg, <daniel@haxx.se>, et al.
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
 ***************************************************************************/
#include "tool_setup.h"

#include <sys/stat.h>

#ifdef HAVE_SIGNAL_H
#include <signal.h>
#endif

#define ENABLE_CURLX_PRINTF
/* use our own printf() functions */
#include "curlx.h"

#include "tool_cfgable.h"
#include "tool_convert.h"
#include "tool_operate.h"
#include "tool_panykey.h"
#include "tool_vms.h"
#include "tool_main.h"

/*
 * This is low-level hard-hacking memory leak tracking and similar. Using
 * the library level code from this client-side is ugly, but we do this
 * anyway for convenience.
 */
#include "memdebug.h" /* keep this as LAST include */

#ifdef __VMS
/*
 * vms_show is a global variable, used in main() as parameter for
 * function vms_special_exit() to allow proper curl tool exiting.
 * Its value may be set in other tool_*.c source files thanks to
 * forward declaration present in tool_vms.h
 */
int vms_show = 0;
#endif

/* if we build a static library for unit tests, there is no main() function */
#ifndef UNITTESTS

/*
 * Ensure that file descriptors 0, 1 and 2 (stdin, stdout, stderr) are
 * open before starting to run.  Otherwise, the first three network
 * sockets opened by curl could be used for input sources, downloaded data
 * or error logs as they will effectively be stdin, stdout and/or stderr.
 */
static void main_checkfds(void)
{
#ifdef HAVE_PIPE
  int fd[2] = { STDIN_FILENO, STDIN_FILENO };
  while(fd[0] == STDIN_FILENO ||
        fd[0] == STDOUT_FILENO ||
        fd[0] == STDERR_FILENO ||
        fd[1] == STDIN_FILENO ||
        fd[1] == STDOUT_FILENO ||
        fd[1] == STDERR_FILENO)
    if(pipe(fd) < 0)
      return;   /* Out of handles. This isn't really a big problem now, but
                   will be when we try to create a socket later. */
  close(fd[0]);
  close(fd[1]);
#endif
}

/*
** curl tool main function.
*/
int main(int argc, char *argv[])
{
  int res;
  struct Configurable config;

  memset(&config, 0, sizeof(struct Configurable));

  config.errors = stderr; /* default errors to stderr */

  main_checkfds();

#if defined(HAVE_SIGNAL) && defined(SIGPIPE)
  (void)signal(SIGPIPE, SIG_IGN);
#endif

  res = operate(&config, argc, argv);

#ifdef __SYMBIAN32__
  if(config.showerror)
    tool_pressanykey();
#endif

  free_config_fields(&config);

#ifdef __NOVELL_LIBC__
  if(getenv("_IN_NETWARE_BASH_") == NULL)
    tool_pressanykey();
#endif

#ifdef __VMS
  vms_special_exit(res, vms_show);
#else
  return res;
#endif
}

#endif /* ndef UNITTESTS */
