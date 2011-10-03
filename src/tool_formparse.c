/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2011, Daniel Stenberg, <daniel@haxx.se>, et al.
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
#include "setup.h"

#include <curl/curl.h>

#include "rawstr.h"

#define ENABLE_CURLX_PRINTF
/* use our own printf() functions */
#include "curlx.h"

#include "tool_cfgable.h"
#include "tool_mfiles.h"
#include "tool_msgs.h"
#include "tool_formparse.h"

#include "memdebug.h" /* keep this as LAST include */

/***************************************************************************
 *
 * formparse()
 *
 * Reads a 'name=value' parameter and builds the appropriate linked list.
 *
 * Specify files to upload with 'name=@filename'. Supports specified
 * given Content-Type of the files. Such as ';type=<content-type>'.
 *
 * If literal_value is set, any initial '@' or '<' in the value string
 * loses its special meaning, as does any embedded ';type='.
 *
 * You may specify more than one file for a single name (field). Specify
 * multiple files by writing it like:
 *
 * 'name=@filename,filename2,filename3'
 *
 * If you want content-types specified for each too, write them like:
 *
 * 'name=@filename;type=image/gif,filename2,filename3'
 *
 * If you want custom headers added for a single part, write them in a separate
 * file and do like this:
 *
 * 'name=foo;headers=@headerfile' or why not
 * 'name=@filemame;headers=@headerfile'
 *
 * To upload a file, but to fake the file name that will be included in the
 * formpost, do like this:
 *
 * 'name=@filename;filename=/dev/null'
 *
 * This function uses curl_formadd to fulfill it's job. Is heavily based on
 * the old curl_formparse code.
 *
 ***************************************************************************/

#define FORM_FILE_SEPARATOR ','
#define FORM_TYPE_SEPARATOR ';'

int formparse(struct Configurable *config,
              const char *input,
              struct curl_httppost **httppost,
              struct curl_httppost **last_post,
              bool literal_value)
{
  /* nextarg MUST be a string in the format 'name=contents' and we'll
     build a linked list with the info */
  char name[256];
  char *contents = NULL;
  char major[128];
  char minor[128];
  char *contp;
  const char *type = NULL;
  char *sep;
  char *sep2;

  if((1 == sscanf(input, "%255[^=]=", name)) &&
     ((contp = strchr(input, '=')) != NULL)) {
    /* the input was using the correct format */

    /* Allocate the contents */
    contents = strdup(contp+1);
    if(!contents) {
      fprintf(config->errors, "out of memory\n");
      return 1;
    }
    contp = contents;

    if('@' == contp[0] && !literal_value) {

      /* we use the @-letter to indicate file name(s) */

      struct multi_files *multi_start = NULL;
      struct multi_files *multi_current = NULL;

      contp++;

      do {
        /* since this was a file, it may have a content-type specifier
           at the end too, or a filename. Or both. */
        char *ptr;
        char *filename = NULL;

        sep = strchr(contp, FORM_TYPE_SEPARATOR);
        sep2 = strchr(contp, FORM_FILE_SEPARATOR);

        /* pick the closest */
        if(sep2 && (sep2 < sep)) {
          sep = sep2;

          /* no type was specified! */
        }

        type = NULL;

        if(sep) {

          /* if we got here on a comma, don't do much */
          if(FORM_FILE_SEPARATOR == *sep)
            ptr = NULL;
          else
            ptr = sep+1;

          *sep = '\0'; /* terminate file name at separator */

          while(ptr && (FORM_FILE_SEPARATOR!= *ptr)) {

            /* pass all white spaces */
            while(ISSPACE(*ptr))
              ptr++;

            if(checkprefix("type=", ptr)) {
              /* set type pointer */
              type = &ptr[5];

              /* verify that this is a fine type specifier */
              if(2 != sscanf(type, "%127[^/]/%127[^;,\n]",
                             major, minor)) {
                warnf(config, "Illegally formatted content-type field!\n");
                Curl_safefree(contents);
                FreeMultiInfo(&multi_start, &multi_current);
                return 2; /* illegal content-type syntax! */
              }

              /* now point beyond the content-type specifier */
              sep = (char *)type + strlen(major)+strlen(minor)+1;

              /* there's a semicolon following - we check if it is a filename
                 specified and if not we simply assume that it is text that
                 the user wants included in the type and include that too up
                 to the next zero or semicolon. */
              if((*sep==';') && !checkprefix(";filename=", sep)) {
                sep2 = strchr(sep+1, ';');
                if(sep2)
                  sep = sep2;
                else
                  sep = sep + strlen(sep); /* point to end of string */
              }

              if(*sep) {
                *sep = '\0'; /* zero terminate type string */

                ptr = sep+1;
              }
              else
                ptr = NULL; /* end */
            }
            else if(checkprefix("filename=", ptr)) {
              filename = &ptr[9];
              ptr = strchr(filename, FORM_TYPE_SEPARATOR);
              if(!ptr) {
                ptr = strchr(filename, FORM_FILE_SEPARATOR);
              }
              if(ptr) {
                *ptr = '\0'; /* zero terminate */
                ptr++;
              }
            }
            else
              /* confusion, bail out of loop */
              break;
          }
          /* find the following comma */
          if(ptr)
            sep = strchr(ptr, FORM_FILE_SEPARATOR);
          else
            sep = NULL;
        }
        else {
          sep = strchr(contp, FORM_FILE_SEPARATOR);
        }
        if(sep) {
          /* the next file name starts here */
          *sep = '\0';
          sep++;
        }
        /* if type == NULL curl_formadd takes care of the problem */

        if(!AddMultiFiles(contp, type, filename, &multi_start,
                          &multi_current)) {
          warnf(config, "Error building form post!\n");
          Curl_safefree(contents);
          FreeMultiInfo(&multi_start, &multi_current);
          return 3;
        }
        contp = sep; /* move the contents pointer to after the separator */

      } while(sep && *sep); /* loop if there's another file name */

      /* now we add the multiple files section */
      if(multi_start) {
        struct curl_forms *forms = NULL;
        struct multi_files *ptr = multi_start;
        unsigned int i, count = 0;
        while(ptr) {
          ptr = ptr->next;
          ++count;
        }
        forms = malloc((count+1)*sizeof(struct curl_forms));
        if(!forms) {
          fprintf(config->errors, "Error building form post!\n");
          Curl_safefree(contents);
          FreeMultiInfo(&multi_start, &multi_current);
          return 4;
        }
        for(i = 0, ptr = multi_start; i < count; ++i, ptr = ptr->next) {
          forms[i].option = ptr->form.option;
          forms[i].value = ptr->form.value;
        }
        forms[count].option = CURLFORM_END;
        FreeMultiInfo(&multi_start, &multi_current);
        if(curl_formadd(httppost, last_post,
                        CURLFORM_COPYNAME, name,
                        CURLFORM_ARRAY, forms, CURLFORM_END) != 0) {
          warnf(config, "curl_formadd failed!\n");
          Curl_safefree(forms);
          Curl_safefree(contents);
          return 5;
        }
        Curl_safefree(forms);
      }
    }
    else {
      struct curl_forms info[4];
      int i = 0;
      char *ct = literal_value ? NULL : strstr(contp, ";type=");

      info[i].option = CURLFORM_COPYNAME;
      info[i].value = name;
      i++;

      if(ct) {
        info[i].option = CURLFORM_CONTENTTYPE;
        info[i].value = &ct[6];
        i++;
        ct[0] = '\0'; /* zero terminate here */
      }

      if(contp[0]=='<' && !literal_value) {
        info[i].option = CURLFORM_FILECONTENT;
        info[i].value = contp+1;
        i++;
        info[i].option = CURLFORM_END;

        if(curl_formadd(httppost, last_post,
                        CURLFORM_ARRAY, info, CURLFORM_END ) != 0) {
          warnf(config, "curl_formadd failed, possibly the file %s is bad!\n",
                contp+1);
          Curl_safefree(contents);
          return 6;
        }
      }
      else {
#ifdef CURL_DOES_CONVERSIONS
        if(convert_to_network(contp, strlen(contp))) {
          warnf(config, "curl_formadd failed!\n");
          Curl_safefree(contents);
          return 7;
        }
#endif
        info[i].option = CURLFORM_COPYCONTENTS;
        info[i].value = contp;
        i++;
        info[i].option = CURLFORM_END;
        if(curl_formadd(httppost, last_post,
                        CURLFORM_ARRAY, info, CURLFORM_END) != 0) {
          warnf(config, "curl_formadd failed!\n");
          Curl_safefree(contents);
          return 8;
        }
      }
    }

  }
  else {
    warnf(config, "Illegally formatted input field!\n");
    return 1;
  }
  Curl_safefree(contents);
  return 0;
}

