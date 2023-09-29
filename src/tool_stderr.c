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
#include "tool_stderr.h"
#include "tool_msgs.h"

#include "memdebug.h" /* keep this as LAST include */

FILE *tool_stderr;

void tool_init_stderr(void)
{
  /* !checksrc! disable STDERR 1 */
  tool_stderr = stderr;
}

void tool_set_stderr_file(struct GlobalConfig *global, char *filename)
{
  FILE *fp;

  if(!filename)
    return;

  if(!strcmp(filename, "-")) {
    tool_stderr = stdout;
    return;
  }

  /* precheck that filename is accessible to lessen the chance that the
     subsequent freopen will fail. */
  fp = fopen(filename, FOPEN_WRITETEXT);
  if(!fp) {
    warnf(global, "Warning: Failed to open %s", filename);
    return;
  }
  fclose(fp);

  /* freopen the actual stderr (stdio.h stderr) instead of tool_stderr since
     the latter may be set to stdout. */
  /* !checksrc! disable STDERR 1 */
  fp = freopen(filename, FOPEN_WRITETEXT, stderr);
  if(!fp) {
    /* stderr may have been closed by freopen. there is nothing to be done. */
    DEBUGASSERT(0);
    return;
  }
  /* !checksrc! disable STDERR 1 */
  tool_stderr = stderr;
}
