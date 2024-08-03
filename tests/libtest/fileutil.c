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
#include "curl_setup.h"
#include <curl/curl.h>
#include "fileutil.h"
#include "memdebug.h"

int loadfile(const char *filename, void **filedata, size_t *filesize)
{
  size_t datasize = 0;
  void *data = NULL;
  if(filename) {
    FILE *fInCert = fopen(filename, "rb");

    if(fInCert) {
      long cert_tell = 0;
      bool continue_reading = fseek(fInCert, 0, SEEK_END) == 0;
      if(continue_reading)
        cert_tell = ftell(fInCert);
      if(cert_tell < 0)
        continue_reading = FALSE;
      else
        datasize = (size_t)cert_tell;
      if(continue_reading)
        continue_reading = fseek(fInCert, 0, SEEK_SET) == 0;
      if(continue_reading)
        data = malloc(datasize + 1);
      if((!data) ||
         ((int)fread(data, datasize, 1, fInCert) != 1))
        continue_reading = FALSE;
      fclose(fInCert);
      if(!continue_reading) {
        free(data);
        datasize = 0;
        data = NULL;
      }
   }
  }
  *filesize = datasize;
  *filedata = data;
  return data ? 1 : 0;
}
