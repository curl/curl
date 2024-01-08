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
#include "tool_setup.h"

#define ENABLE_CURLX_PRINTF
/* use our own printf() functions */
#include "curlx.h"

#include "tool_cfgable.h"
#include "tool_msgs.h"

#include "memdebug.h" /* keep this as LAST include */

#define WARN_PREFIX "Warning: "
#define NOTE_PREFIX "Note: "
#define ERROR_PREFIX "curl: "

static void voutf(struct GlobalConfig *config,
                  const char *prefix,
                  const char *fmt,
                  va_list ap) CURL_PRINTF(3, 0);

static void voutf(struct GlobalConfig *config,
                  const char *prefix,
                  const char *fmt,
                  va_list ap)
{
  size_t width = (79 - strlen(prefix));
  DEBUGASSERT(!strchr(fmt, '\n'));
  if(!config->silent) {
    size_t len;
    char *ptr;
    char *print_buffer;

#ifdef __clang__
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wformat-nonliteral"
#endif
    print_buffer = curlx_mvaprintf(fmt, ap);
#ifdef __clang__
#pragma clang diagnostic pop
#endif
    if(!print_buffer)
      return;
    len = strlen(print_buffer);

    ptr = print_buffer;
    while(len > 0) {
      fputs(prefix, tool_stderr);

      if(len > width) {
        size_t cut = width-1;

        while(!ISBLANK(ptr[cut]) && cut) {
          cut--;
        }
        if(0 == cut)
          /* not a single cutting position was found, just cut it at the
             max text width then! */
          cut = width-1;

        (void)fwrite(ptr, cut + 1, 1, tool_stderr);
        fputs("\n", tool_stderr);
        ptr += cut + 1; /* skip the space too */
        len -= cut + 1;
      }
      else {
        fputs(ptr, tool_stderr);
        fputs("\n", tool_stderr);
        len = 0;
      }
    }
    curl_free(print_buffer);
  }
}

/*
 * Emit 'note' formatted message on configured 'errors' stream, if verbose was
 * selected.
 */
void notef(struct GlobalConfig *config, const char *fmt, ...)
{
  va_list ap;
  va_start(ap, fmt);
  if(config->tracetype)
    voutf(config, NOTE_PREFIX, fmt, ap);
  va_end(ap);
}

/*
 * Emit warning formatted message on configured 'errors' stream unless
 * mute (--silent) was selected.
 */
void warnf(struct GlobalConfig *config, const char *fmt, ...)
{
  va_list ap;
  va_start(ap, fmt);
  voutf(config, WARN_PREFIX, fmt, ap);
  va_end(ap);
}

/*
 * Emit help formatted message on given stream. This is for errors with or
 * related to command line arguments.
 */
void helpf(FILE *errors, const char *fmt, ...)
{
  if(fmt) {
    va_list ap;
    va_start(ap, fmt);
    DEBUGASSERT(!strchr(fmt, '\n'));
    fputs("curl: ", errors); /* prefix it */
#ifdef __clang__
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wformat-nonliteral"
#endif
    vfprintf(errors, fmt, ap);
#ifdef __clang__
#pragma clang diagnostic pop
#endif
    va_end(ap);
    fputs("\n", errors); /* newline it */
  }
  fprintf(errors, "curl: try 'curl --help' "
#ifdef USE_MANUAL
          "or 'curl --manual' "
#endif
          "for more information\n");
}

/*
 * Emit error message on error stream if not muted. When errors are not tied
 * to command line arguments, use helpf() for such errors.
 */
void errorf(struct GlobalConfig *config, const char *fmt, ...)
{
  if(!config->silent || config->showerror) {
    va_list ap;
    va_start(ap, fmt);
    voutf(config, ERROR_PREFIX, fmt, ap);
    va_end(ap);
  }
}
