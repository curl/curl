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
 * - Daniel Stenberg <Daniel.Stenberg@haxx.nu>
 *
 * 	http://curl.haxx.nu
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

#include <stdio.h>
#include <string.h>

#include "writeout.h"

typedef enum {
  VAR_NONE,       /* must be the first */
  VAR_TOTAL_TIME,
  VAR_NAMELOOKUP_TIME,
  VAR_CONNECT_TIME,
  VAR_PRETRANSFER_TIME,
  VAR_SIZE_DOWNLOAD,
  VAR_SIZE_UPLOAD,
  VAR_SPEED_DOWNLOAD,
  VAR_SPEED_UPLOAD,
  VAR_HTTP_CODE,
  VAR_EFFECTIVE_URL,
  VAR_NUM_OF_VARS /* must be the last */
} replaceid;

struct variable {
  char *name;
  replaceid id;
};


static struct variable replacements[]={
  {"url_effective", VAR_EFFECTIVE_URL},
  {"http_code", VAR_HTTP_CODE},
  {"time_total", VAR_TOTAL_TIME},
  {"time_namelookup", VAR_NAMELOOKUP_TIME},
  {"time_connect", VAR_CONNECT_TIME},
  {"time_pretransfer", VAR_PRETRANSFER_TIME},
  {"size_download", VAR_SIZE_DOWNLOAD},
  {"size_upload", VAR_SIZE_UPLOAD},
  {"speed_download", VAR_SPEED_DOWNLOAD},
  {"speed_upload", VAR_SPEED_UPLOAD},
  {NULL}
};

void WriteOut(struct UrlData *data)
{
  FILE *stream = stdout;
  char *ptr=data->writeinfo;
  while(*ptr) {
    if('%' == *ptr) {
      if('%' == ptr[1]) {
        /* an escaped %-letter */
        fputc('%', stream);
        ptr+=2;
      }
      else {
        /* this is meant as a variable to output */
        char *end;
        int i;
        if(('{' == ptr[1]) && (end=strchr(ptr, '}'))) {
          ptr+=2; /* pass the % and the { */
          *end=0; /* zero terminate */
          for(i=0; replacements[i].name; i++) {
            if(strequal(ptr, replacements[i].name)) {
              switch(replacements[i].id) {
              case VAR_EFFECTIVE_URL:
                fprintf(stream, "%s", data->url?data->url:"");
                break;
              case VAR_TOTAL_TIME:
                fprintf(stream, "%.3f", data->progress.timespent);
                break;
              case VAR_NAMELOOKUP_TIME:
                fprintf(stream, "%.3f", tvdiff(data->progress.t_nslookup,
                                               data->progress.start));
                break;
              case VAR_CONNECT_TIME:
                fprintf(stream, "%.3f", tvdiff(data->progress.t_connect,
                                               data->progress.start));
                break;
              case VAR_PRETRANSFER_TIME:
                fprintf(stream, "%.3f", tvdiff(data->progress.t_pretransfer,
                                               data->progress.start));
                break;
              case VAR_SIZE_UPLOAD:
                fprintf(stream, "%.0f", data->progress.uploaded);
                break;
              case VAR_SIZE_DOWNLOAD:
                fprintf(stream, "%.0f", data->progress.downloaded);
                break;
              case VAR_SPEED_DOWNLOAD:
                fprintf(stream, "%.2f", data->progress.dlspeed);
                break;
              case VAR_SPEED_UPLOAD:
                fprintf(stream, "%.2f", data->progress.ulspeed);
                break;
              }
              break;
            }
          }
          ptr=end+1; /* pass the end */
        }
        else {
          /* illegal syntax, then just output the characters that are used */
          fputc('%', stream);
          fputc(ptr[1], stream);
          ptr+=2;
        }
      }
    }
    else if('\\' == *ptr) {
      switch(ptr[1]) {
      case 'r':
        fputc('\r', stream);
        break;
      case 'n':
        fputc('\n', stream);
        break;
      case 't':
        fputc('\t', stream);
        break;
      default:
        /* unknown, just output this */
        fputc(*ptr, stream);
        fputc(ptr[1], stream);
        break;
      }
      ptr+=2;
    }
    else {
      fputc(*ptr, stream);
      ptr++;
    }
  }
  
}
