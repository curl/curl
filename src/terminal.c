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

#ifdef HAVE_SYS_IOCTL_H
#include <sys/ioctl.h>
#endif

#include "terminal.h"

#ifdef HAVE_TERMIOS_H
#  include <termios.h>
#elif defined(HAVE_TERMIO_H)
#  include <termio.h>
#endif

static unsigned int terminal_env_dimension(const char *name,
                                           unsigned int minimum)
{
  unsigned int value = 0;
  char *env = curl_getenv(name);

  if(env) {
    curl_off_t num;
    const char *ptr = env;

    if(!curlx_str_number(&ptr, &num, 10000) && (num >= (curl_off_t)minimum))
      value = (unsigned int)num;
    curl_free(env);
  }

  return value;
}

void get_terminal_size(unsigned int *width, unsigned int *height)
{
  int cols = 0;
  int rows = 0;

  DEBUGASSERT(width);
  DEBUGASSERT(height);

  *width = terminal_env_dimension("COLUMNS", 1);
  *height = terminal_env_dimension("LINES", 1);

  if(*width && *height)
    return;

#ifdef TIOCGSIZE
  {
    struct ttysize ts;

    if(!ioctl(STDIN_FILENO, TIOCGSIZE, &ts)) {
      cols = (int)ts.ts_cols;
      rows = (int)ts.ts_lines;
    }
  }
#elif defined(TIOCGWINSZ)
  {
    struct winsize ts;

    if(!ioctl(STDIN_FILENO, TIOCGWINSZ, &ts)) {
      cols = (int)ts.ws_col;
      rows = (int)ts.ws_row;
    }
  }
#elif defined(_WIN32) && !defined(CURL_WINDOWS_UWP)
  {
    HANDLE stderr_hnd = GetStdHandle(STD_ERROR_HANDLE);
    CONSOLE_SCREEN_BUFFER_INFO console_info;

    if((stderr_hnd != INVALID_HANDLE_VALUE) &&
       GetConsoleScreenBufferInfo(stderr_hnd, &console_info)) {
      /*
       * Do not use +1 to get the true screen-width since writing a
       * character at the right edge causes a line wrap.
       */
      cols = (int)(console_info.srWindow.Right - console_info.srWindow.Left);
      rows = (int)(console_info.srWindow.Bottom -
                   console_info.srWindow.Top + 1);
    }
  }
#endif /* TIOCGSIZE */

  if(!*width && cols > 0 && cols < 10000)
    *width = (unsigned int)cols;
  if(!*height && rows > 0 && rows < 10000)
    *height = (unsigned int)rows;
}

bool terminal_is_attached(void)
{
  return isatty(STDIN_FILENO) != 0;
}

/*
 * get_terminal_columns() returns the number of columns in the current
 * terminal. It returns 79 on failure. Also, the number can be big.
 */
unsigned int get_terminal_columns(void)
{
  unsigned int width = 0;
  unsigned int height = 0;

  get_terminal_size(&width, &height);
  if(width && width <= 20)
    width = 0;
  if(!width)
    width = 79;
  return width; /* 79 for unknown, might also be tiny or enormous */
}
