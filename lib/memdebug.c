#ifdef MALLOCDEBUG
/*****************************************************************************
 *                                  _   _ ____  _     
 *  Project                     ___| | | |  _ \| |    
 *                             / __| | | | |_) | |    
 *                            | (__| |_| |  _ <| |___ 
 *                             \___|\___/|_| \_\_____|
 *
 *  The contents of this file are subject to the Mozilla Public License
 *  Version 1.0 (the "License"); you may not use this file except in
 *  compliance with the License. You may obtain a copy of the License at
 *  http://www.mozilla.org/MPL/
 *
 *  Software distributed under the License is distributed on an "AS IS"
 *  basis, WITHOUT WARRANTY OF ANY KIND, either express or implied. See the
 *  License for the specific language governing rights and limitations
 *  under the License.
 *
 *  The Original Code is Curl.
 *
 *  The Initial Developer of the Original Code is Daniel Stenberg.
 *
 *  Portions created by the Initial Developer are Copyright (C) 1999.
 *  All Rights Reserved.
 *
 * ------------------------------------------------------------
 * Main author:
 * - Daniel Stenberg <daniel@haxx.se>
 *
 * 	http://curl.haxx.se
 *
 * $Source$
 * $Revision$
 * $Date$
 * $Author$
 * $State$
 * $Locker$
 *
 * ------------------------------------------------------------
 ****************************************************************************/

#include "setup.h"

#include <curl/curl.h>
#include "urldata.h"
#include <stdio.h>
#include <string.h>

/*
 * Note that these debug functions are very simple and they are meant to
 * remain so. For advanced analysis, record a log file and write perl scripts
 * to analyze them!
 *
 * Don't use these with multithreaded test programs!
 */

FILE *logfile;

/* this sets the log file name */
void curl_memdebug(char *logname)
{
  logfile = fopen(logname, "w");
}


void *curl_domalloc(size_t size, int line, char *source)
{
  void *mem=(malloc)(size);
  fprintf(logfile?logfile:stderr, "MEM %s:%d malloc(%d) = %p\n",
          source, line, size, mem);
  return mem;
}

char *curl_dostrdup(char *str, int line, char *source)
{
  char *mem=(strdup)(str);
  size_t len=strlen(str)+1;
  fprintf(logfile?logfile:stderr, "MEM %s:%d strdup(%p) (%d) = %p\n",
          source, line, str, len, mem);
  return mem;
}

void *curl_dorealloc(void *ptr, size_t size, int line, char *source)
{
  void *mem=(realloc)(ptr, size);
  fprintf(logfile?logfile:stderr, "MEM %s:%d realloc(%p, %d) = %p\n",
          source, line, ptr, size, mem);
  return mem;
}

void curl_dofree(void *ptr, int line, char *source)
{
  (free)(ptr);
  fprintf(logfile?logfile:stderr, "MEM %s:%d free(%p)\n",
          source, line, ptr);
}

#endif /* MALLOCDEBUG */
