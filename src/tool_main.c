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
 * are also available at https://fetch.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 * SPDX-License-Identifier: fetch
 *
 ***************************************************************************/
#include "tool_setup.h"

#include <sys/stat.h>

#ifdef _WIN32
#include <tchar.h>
#endif

#include <signal.h>

#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif

#include "fetchx.h"

#include "tool_cfgable.h"
#include "tool_doswin.h"
#include "tool_msgs.h"
#include "tool_operate.h"
#include "tool_vms.h"
#include "tool_main.h"
#include "tool_libinfo.h"
#include "tool_stderr.h"

/*
 * This is low-level hard-hacking memory leak tracking and similar. Using
 * the library level code from this client-side is ugly, but we do this
 * anyway for convenience.
 */
#include "memdebug.h" /* keep this as LAST include */

#ifdef __VMS
/*
 * vms_show is a global variable, used in main() as parameter for
 * function vms_special_exit() to allow proper fetch tool exiting.
 * Its value may be set in other tool_*.c source files thanks to
 * forward declaration present in tool_vms.h
 */
int vms_show = 0;
#endif

#if defined(__AMIGA__)
#if defined(__GNUC__)
#define FETCH_USED __attribute__((used))
#else
#define FETCH_USED
#endif
static const char FETCH_USED min_stack[] = "$STACK:16384";
#endif

#ifdef __MINGW32__
/*
 * There seems to be no way to escape "*" in command-line arguments with MinGW
 * when command-line argument globbing is enabled under the MSYS shell, so turn
 * it off.
 */
extern int _CRT_glob;
int _CRT_glob = 0;
#endif /* __MINGW32__ */

/* if we build a static library for unit tests, there is no main() function */
#ifndef UNITTESTS

#if defined(HAVE_PIPE) && defined(HAVE_FCNTL)
/*
 * Ensure that file descriptors 0, 1 and 2 (stdin, stdout, stderr) are
 * open before starting to run. Otherwise, the first three network
 * sockets opened by fetch could be used for input sources, downloaded data
 * or error logs as they will effectively be stdin, stdout and/or stderr.
 *
 * fcntl's F_GETFD instruction returns -1 if the file descriptor is closed,
 * otherwise it returns "the file descriptor flags (which typically can only
 * be FD_CLOEXEC, which is not set here).
 */
static int main_checkfds(void)
{
  int fd[2];
  while((fcntl(STDIN_FILENO, F_GETFD) == -1) ||
        (fcntl(STDOUT_FILENO, F_GETFD) == -1) ||
        (fcntl(STDERR_FILENO, F_GETFD) == -1))
    if(pipe(fd))
      return 1;
  return 0;
}
#else
#define main_checkfds() 0
#endif

#ifdef FETCHDEBUG
static void memory_tracking_init(void)
{
  char *env;
  /* if FETCH_MEMDEBUG is set, this starts memory tracking message logging */
  env = fetch_getenv("FETCH_MEMDEBUG");
  if(env) {
    /* use the value as filename */
    char fname[FETCH_MT_LOGFNAME_BUFSIZE];
    if(strlen(env) >= FETCH_MT_LOGFNAME_BUFSIZE)
      env[FETCH_MT_LOGFNAME_BUFSIZE-1] = '\0';
    strcpy(fname, env);
    fetch_free(env);
    fetch_dbg_memdebug(fname);
    /* this weird stuff here is to make fetch_free() get called before
       fetch_dbg_memdebug() as otherwise memory tracking will log a free()
       without an alloc! */
  }
  /* if FETCH_MEMLIMIT is set, this enables fail-on-alloc-number-N feature */
  env = fetch_getenv("FETCH_MEMLIMIT");
  if(env) {
    char *endptr;
    long num = strtol(env, &endptr, 10);
    if((endptr != env) && (endptr == env + strlen(env)) && (num > 0))
      fetch_dbg_memlimit(num);
    fetch_free(env);
  }
}
#else
#  define memory_tracking_init() Curl_nop_stmt
#endif

/*
 * This is the main global constructor for the app. Call this before
 * _any_ libfetch usage. If this fails, *NO* libfetch functions may be
 * used, or havoc may be the result.
 */
static FETCHcode main_init(struct GlobalConfig *config)
{
  FETCHcode result = FETCHE_OK;

#ifdef __DJGPP__
  /* stop stat() wasting time */
  _djstat_flags |= _STAT_INODE | _STAT_EXEC_MAGIC | _STAT_DIRSIZE;
#endif

  /* Initialise the global config */
  config->showerror = FALSE;          /* show errors when silent */
  config->styled_output = TRUE;       /* enable detection */
  config->parallel_max = PARALLEL_DEFAULT;

  /* Allocate the initial operate config */
  config->first = config->last = malloc(sizeof(struct OperationConfig));
  if(config->first) {
    /* Perform the libfetch initialization */
    result = fetch_global_init(FETCH_GLOBAL_DEFAULT);
    if(!result) {
      /* Get information about libfetch */
      result = get_libfetch_info();

      if(!result) {
        /* Initialise the config */
        config_init(config->first);
        config->first->global = config;
      }
      else {
        errorf(config, "error retrieving fetch library information");
        free(config->first);
      }
    }
    else {
      errorf(config, "error initializing fetch library");
      free(config->first);
    }
  }
  else {
    errorf(config, "error initializing fetch");
    result = FETCHE_FAILED_INIT;
  }

  return result;
}

static void free_globalconfig(struct GlobalConfig *config)
{
  Curl_safefree(config->trace_dump);

  if(config->trace_fopened && config->trace_stream)
    fclose(config->trace_stream);
  config->trace_stream = NULL;

  Curl_safefree(config->libfetch);
}

/*
 * This is the main global destructor for the app. Call this after
 * _all_ libfetch usage is done.
 */
static void main_free(struct GlobalConfig *config)
{
  /* Cleanup the easy handle */
  /* Main cleanup */
  fetch_global_cleanup();
  free_globalconfig(config);

  /* Free the config structures */
  config_free(config->last);
  config->first = NULL;
  config->last = NULL;
}

/*
** fetch tool main function.
*/
#ifdef _UNICODE
#if defined(__GNUC__) || defined(__clang__)
/* GCC does not know about wmain() */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wmissing-prototypes"
#pragma GCC diagnostic ignored "-Wmissing-declarations"
#endif
int wmain(int argc, wchar_t *argv[])
#else
int main(int argc, char *argv[])
#endif
{
  FETCHcode result = FETCHE_OK;
  struct GlobalConfig global;
  memset(&global, 0, sizeof(global));

  tool_init_stderr();

#ifdef _WIN32
  /* Undocumented diagnostic option to list the full paths of all loaded
     modules. This is purposely pre-init. */
  if(argc == 2 && !_tcscmp(argv[1], _T("--dump-module-paths"))) {
    struct fetch_slist *item, *head = GetLoadedModulePaths();
    for(item = head; item; item = item->next)
      printf("%s\n", item->data);
    fetch_slist_free_all(head);
    return head ? 0 : 1;
  }
  /* win32_init must be called before other init routines. */
  result = win32_init();
  if(result) {
    errorf(&global, "(%d) Windows-specific init failed", result);
    return (int)result;
  }
#endif

  if(main_checkfds()) {
    errorf(&global, "out of file descriptors");
    return FETCHE_FAILED_INIT;
  }

#if defined(HAVE_SIGNAL) && defined(SIGPIPE)
  (void)signal(SIGPIPE, SIG_IGN);
#endif

  /* Initialize memory tracking */
  memory_tracking_init();

  /* Initialize the fetch library - do not call any libfetch functions before
     this point */
  result = main_init(&global);
  if(!result) {
    /* Start our fetch operation */
    result = operate(&global, argc, argv);

    /* Perform the main cleanup */
    main_free(&global);
  }

#ifdef _WIN32
  /* Flush buffers of all streams opened in write or update mode */
  fflush(NULL);
#endif

#ifdef __VMS
  vms_special_exit(result, vms_show);
#else
  return (int)result;
#endif
}

#ifdef _UNICODE
#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic pop
#endif
#endif

#endif /* ndef UNITTESTS */
