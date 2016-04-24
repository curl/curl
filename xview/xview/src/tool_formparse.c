/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2015, Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at https://curl.haxx.se/docs/copyright.html.
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

#include "rawstr.h"

#define ENABLE_CURLX_PRINTF
/* use our own printf() functions */
#include "curlx.h"

#include "tool_cfgable.h"
#include "tool_mfiles.h"
#include "tool_msgs.h"
#include "tool_formparse.h"

#include "memdebug.h" /* keep this as LAST include */


/*
 * helper function to get a word from form param
 * after call get_parm_word, str either point to string end
 * or point to any of end chars.
 */
static char *get_param_word(char **str, char **end_pos)
{
  char *ptr = *str;
  char *word_begin = NULL;
  char *ptr2;
  char *escape = NULL;
  const char *end_chars = ";,";

  /* the first non-space char is here */
  word_begin = ptr;
  if(*ptr == '"') {
    ++ptr;
    while(*ptr) {
      if(*ptr == '\\') {
        if(ptr[1] == '\\' || ptr[1] == '"') {
          /* remember the first escape position */
          if(!escape)
            escape = ptr;
          /* skip escape of back-slash or double-quote */
          ptr += 2;
          continue;
        }
      }
      if(*ptr == '"') {
        *end_pos = ptr;
        if(escape) {
          /* has escape, we restore the unescaped string here */
          ptr = ptr2 = escape;
          do {
            if(*ptr == '\\' && (ptr[1] == '\\' || ptr[1] == '"'))
              ++ptr;
            *ptr2++ = *ptr++;
          }
          while(ptr < *end_pos);
          *end_pos = ptr2;
        }
        while(*ptr && NULL==strchr(end_chars, *ptr))
          ++ptr;
        *str = ptr;
        return word_begin+1;
      }
      ++ptr;
    }
    /* end quote is missing, treat it as non-quoted. */
    ptr = word_begin;
  }

  while(*ptr && NULL==strchr(end_chars, *ptr))
    ++ptr;
  *str = *end_pos = ptr;
  return word_begin;
}

/***************************************************************************
 *
 * formparse()
 *
 * Reads a 'name=value' parameter and builds the appropriate linked list.
 *
 * Specify files to upload with 'name=@filename', or 'name=@"filename"'
 * in case the filename contain ',' or ';'. Supports specified
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
 * or use double-quotes quote the filename:
 *
 * 'name=@"filename","filename2","filename3"'
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
 * 'name=@filename;filename=/dev/null' or quote the faked filename like:
 * 'name=@filename;filename="play, play, and play.txt"'
 *
 * If filename/path contains ',' or ';', it must be quoted by double-quotes,
 * else curl will fail to figure out the correct filename. if the filename
 * tobe quoted contains '"' or '\', '"' and '\' must be escaped by backslash.
 *
 * This function uses curl_formadd to fulfill it's job. Is heavily based on
 * the old curl_formparse code.
 *
 ***************************************************************************/

int formparse(struct OperationConfig *config,
              const char *input,
              struct curl_httppost **httppost,
              struct curl_httppost **last_post,
              bool literal_value)
{
  /* nextarg MUST be a string in the format 'name=contents' and we'll
     build a linked list with the info */
  char name[256];
  char *contents = NULL;
  char type_major[128] = "";
  char type_minor[128] = "";
  char *contp;
  const char *type = NULL;
  char *sep;

  if((1 == sscanf(input, "%255[^=]=", name)) &&
     ((contp = strchr(input, '=')) != NULL)) {
    /* the input was using the correct format */

    /* Allocate the contents */
    contents = strdup(contp+1);
    if(!contents) {
      fprintf(config->global->errors, "out of memory\n");
      return 1;
    }
    contp = contents;

    if('@' == contp[0] && !literal_value) {

      /* we use the @-letter to indicate file name(s) */

      struct multi_files *multi_start = NULL;
      struct multi_files *multi_current = NULL;

      char *ptr = contp;
      char *end = ptr + strlen(ptr);

      do {
        /* since this was a file, it may have a content-type specifier
           at the end too, or a filename. Or both. */
        char *filename = NULL;
        char *word_end;
        bool semicolon;

        type = NULL;

        ++ptr;
        contp = get_param_word(&ptr, &word_end);
        semicolon = (';' == *ptr) ? TRUE : FALSE;
        *word_end = '\0'; /* terminate the contp */

        /* have other content, continue parse */
        while(semicolon) {
          /* have type or filename field */
          ++ptr;
          while(*ptr && (ISSPACE(*ptr)))
            ++ptr;

          if(checkprefix("type=", ptr)) {
            /* set type pointer */
            type = &ptr[5];

            /* verify that this is a fine type specifier */
            if(2 != sscanf(type, "%127[^/]/%127[^;,\n]",
                           type_major, type_minor)) {
              warnf(config->global,
                    "Illegally formatted content-type field!\n");
              Curl_safefree(contents);
              FreeMultiInfo(&multi_start, &multi_current);
              return 2; /* illegal content-type syntax! */
            }

            /* now point beyond the content-type specifier */
            sep = (char *)type + strlen(type_major)+strlen(type_minor)+1;

            /* there's a semicolon following - we check if it is a filename
               specified and if not we simply assume that it is text that
               the user wants included in the type and include that too up
               to the next sep. */
            ptr = sep;
            if(*sep==';') {
              if(!checkprefix(";filename=", sep)) {
                ptr = sep + 1;
                (void)get_param_word(&ptr, &sep);
                semicolon = (';' == *ptr) ? TRUE : FALSE;
              }
            }
            else
              semicolon = FALSE;

            if(*sep)
              *sep = '\0'; /* zero terminate type string */
          }
          else if(checkprefix("filename=", ptr)) {
            ptr += 9;
            filename = get_param_word(&ptr, &word_end);
            semicolon = (';' == *ptr) ? TRUE : FALSE;
            *word_end = '\0';
          }
          else {
            /* unknown prefix, skip to next block */
            char *unknown = NULL;
            unknown = get_param_word(&ptr, &word_end);
            semicolon = (';' == *ptr) ? TRUE : FALSE;
            if(*unknown) {
              *word_end = '\0';
              warnf(config->global, "skip unknown form field: %s\n", unknown);
            }
          }
        }
        /* now ptr point to comma or string end */


        /* if type == NULL curl_formadd takes care of the problem */

        if(*contp && !AddMultiFiles(contp, type, filename, &multi_start,
                          &multi_current)) {
          warnf(config->global, "Error building form post!\n");
          Curl_safefree(contents);
          FreeMultiInfo(&multi_start, &multi_current);
          return 3;
        }

        /* *ptr could be '\0', so we just check with the string end */
      } while(ptr < end); /* loop if there's another file name */

      /* now we add the multiple files section */
      if(multi_start) {
        struct curl_forms *forms = NULL;
        struct multi_files *start = multi_start;
        unsigned int i, count = 0;
        while(start) {
          start = start->next;
          ++count;
        }
        forms = malloc((count+1)*sizeof(struct curl_forms));
        if(!forms) {
          fprintf(config->global->errors, "Error building form post!\n");
          Curl_safefree(contents);
          FreeMultiInfo(&multi_start, &multi_current);
          return 4;
        }
        for(i = 0, start = multi_start; i < count; ++i, start = start->next) {
          forms[i].option = start->form.option;
          forms[i].value = start->form.value;
        }
        forms[count].option = CURLFORM_END;
        FreeMultiInfo(&multi_start, &multi_current);
        if(curl_formadd(httppost, last_post,
                        CURLFORM_COPYNAME, name,
                        CURLFORM_ARRAY, forms, CURLFORM_END) != 0) {
          warnf(config->global, "curl_formadd failed!\n");
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
          warnf(config->global, "curl_formadd failed, possibly the file %s is "
                "bad!\n", contp + 1);
          Curl_safefree(contents);
          return 6;
        }
      }
      else {
#ifdef CURL_DOES_CONVERSIONS
        if(convert_to_network(contp, strlen(contp))) {
          warnf(config->global, "curl_formadd failed!\n");
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
          warnf(config->global, "curl_formadd failed!\n");
          Curl_safefree(contents);
          return 8;
        }
      }
    }

  }
  else {
    warnf(config->global, "Illegally formatted input field!\n");
    return 1;
  }
  Curl_safefree(contents);
  return 0;
}
