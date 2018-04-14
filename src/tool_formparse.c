/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2017, Daniel Stenberg, <daniel@haxx.se>, et al.
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

#include "mime.h"
#include "strcase.h"

#define ENABLE_CURLX_PRINTF
/* use our own printf() functions */
#include "curlx.h"

#include "tool_cfgable.h"
#include "tool_convert.h"
#include "tool_msgs.h"
#include "tool_binmode.h"
#include "tool_getparam.h"
#include "tool_paramhlp.h"
#include "tool_formparse.h"

#include "memdebug.h" /* keep this as LAST include */

/* Stdin parameters. */
typedef struct {
  char *data;  /* Memory data. */
  curl_off_t origin;  /* File read origin offset. */
  curl_off_t size; /* Data size. */
  curl_off_t curpos; /* Current read position. */
}  standard_input;


/*
 * helper function to get a word from form param
 * after call get_parm_word, str either point to string end
 * or point to any of end chars.
 */
static char *get_param_word(char **str, char **end_pos, char endchar)
{
  char *ptr = *str;
  char *word_begin = NULL;
  char *ptr2;
  char *escape = NULL;

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
        while(*ptr && *ptr != ';' && *ptr != endchar)
          ++ptr;
        *str = ptr;
        return word_begin + 1;
      }
      ++ptr;
    }
    /* end quote is missing, treat it as non-quoted. */
    ptr = word_begin;
  }

  while(*ptr && *ptr != ';' && *ptr != endchar)
    ++ptr;
  *str = *end_pos = ptr;
  return word_begin;
}

/* Append slist item and return -1 if failed. */
static int slist_append(struct curl_slist **plist, const char *data)
{
  struct curl_slist *s = curl_slist_append(*plist, data);

  if(!s)
    return -1;

  *plist = s;
  return 0;
}

/* Read headers from a file and append to list. */
static int read_field_headers(struct OperationConfig *config,
                              const char *filename, FILE *fp,
                              struct curl_slist **pheaders)
{
  size_t hdrlen = 0;
  size_t pos = 0;
  int c;
  bool incomment = FALSE;
  int lineno = 1;
  char hdrbuf[999]; /* Max. header length + 1. */

  for(;;) {
    c = getc(fp);
    if(c == EOF || (!pos && !ISSPACE(c))) {
      /* Strip and flush the current header. */
      while(hdrlen && ISSPACE(hdrbuf[hdrlen - 1]))
        hdrlen--;
      if(hdrlen) {
        hdrbuf[hdrlen] = '\0';
        if(slist_append(pheaders, hdrbuf)) {
          fprintf(config->global->errors,
                  "Out of memory for field headers!\n");
          return -1;
        }
        hdrlen = 0;
      }
    }

    switch(c) {
    case EOF:
      if(ferror(fp)) {
        fprintf(config->global->errors,
                "Header file %s read error: %s\n", filename, strerror(errno));
        return -1;
      }
      return 0;    /* Done. */
    case '\r':
      continue;    /* Ignore. */
    case '\n':
      pos = 0;
      incomment = FALSE;
      lineno++;
      continue;
    case '#':
      if(!pos)
        incomment = TRUE;
      break;
    }

    pos++;
    if(!incomment) {
      if(hdrlen == sizeof hdrbuf - 1) {
        warnf(config->global, "File %s line %d: header too long (truncated)\n",
              filename, lineno);
        c = ' ';
      }
      if(hdrlen <= sizeof hdrbuf - 1)
        hdrbuf[hdrlen++] = (char) c;
    }
  }
  /* NOTREACHED */
}

static int get_param_part(struct OperationConfig *config, char endchar,
                          char **str, char **pdata, char **ptype,
                          char **pfilename, char **pencoder,
                          struct curl_slist **pheaders)
{
  char *p = *str;
  char *type = NULL;
  char *filename = NULL;
  char *encoder = NULL;
  char *endpos;
  char *tp;
  char sep;
  char type_major[128] = "";
  char type_minor[128] = "";
  char *endct = NULL;
  struct curl_slist *headers = NULL;

  if(ptype)
    *ptype = NULL;
  if(pfilename)
    *pfilename = NULL;
  if(pheaders)
    *pheaders = NULL;
  if(pencoder)
    *pencoder = NULL;
  while(ISSPACE(*p))
    p++;
  tp = p;
  *pdata = get_param_word(&p, &endpos, endchar);
  /* If not quoted, strip trailing spaces. */
  if(*pdata == tp)
    while(endpos > *pdata && ISSPACE(endpos[-1]))
      endpos--;
  sep = *p;
  *endpos = '\0';
  while(sep == ';') {
    while(ISSPACE(*++p))
      ;

    if(!endct && checkprefix("type=", p)) {
      for(p += 5; ISSPACE(*p); p++)
        ;
      /* set type pointer */
      type = p;

      /* verify that this is a fine type specifier */
      if(2 != sscanf(type, "%127[^/ ]/%127[^;, \n]", type_major, type_minor)) {
        warnf(config->global, "Illegally formatted content-type field!\n");
        curl_slist_free_all(headers);
        return -1; /* illegal content-type syntax! */
      }

      /* now point beyond the content-type specifier */
      p = type + strlen(type_major) + strlen(type_minor) + 1;
      for(endct = p; *p && *p != ';' && *p != endchar; p++)
        if(!ISSPACE(*p))
          endct = p + 1;
      sep = *p;
    }
    else if(checkprefix("filename=", p)) {
      if(endct) {
        *endct = '\0';
        endct = NULL;
      }
      for(p += 9; ISSPACE(*p); p++)
        ;
      tp = p;
      filename = get_param_word(&p, &endpos, endchar);
      /* If not quoted, strip trailing spaces. */
      if(filename == tp)
        while(endpos > filename && ISSPACE(endpos[-1]))
          endpos--;
      sep = *p;
      *endpos = '\0';
    }
    else if(checkprefix("headers=", p)) {
      if(endct) {
        *endct = '\0';
        endct = NULL;
      }
      p += 8;
      if(*p == '@' || *p == '<') {
        char *hdrfile;
        FILE *fp;
        /* Read headers from a file. */

        do {
          p++;
        } while(ISSPACE(*p));
        tp = p;
        hdrfile = get_param_word(&p, &endpos, endchar);
        /* If not quoted, strip trailing spaces. */
        if(hdrfile == tp)
          while(endpos > hdrfile && ISSPACE(endpos[-1]))
            endpos--;
        sep = *p;
        *endpos = '\0';
        /* TODO: maybe special fopen for VMS? */
        fp = fopen(hdrfile, FOPEN_READTEXT);
        if(!fp)
          warnf(config->global, "Cannot read from %s: %s\n", hdrfile,
                strerror(errno));
        else {
          int i = read_field_headers(config, hdrfile, fp, &headers);

          fclose(fp);
          if(i) {
            curl_slist_free_all(headers);
            return -1;
          }
        }
      }
      else {
        char *hdr;

        while(ISSPACE(*p))
          p++;
        tp = p;
        hdr = get_param_word(&p, &endpos, endchar);
        /* If not quoted, strip trailing spaces. */
        if(hdr == tp)
          while(endpos > hdr && ISSPACE(endpos[-1]))
            endpos--;
        sep = *p;
        *endpos = '\0';
        if(slist_append(&headers, hdr)) {
          fprintf(config->global->errors, "Out of memory for field header!\n");
          curl_slist_free_all(headers);
          return -1;
        }
      }
    }
    else if(checkprefix("encoder=", p)) {
      if(endct) {
        *endct = '\0';
        endct = NULL;
      }
      for(p += 8; ISSPACE(*p); p++)
        ;
      tp = p;
      encoder = get_param_word(&p, &endpos, endchar);
      /* If not quoted, strip trailing spaces. */
      if(encoder == tp)
        while(endpos > encoder && ISSPACE(endpos[-1]))
          endpos--;
      sep = *p;
      *endpos = '\0';
    }
    else if(endct) {
      /* This is part of content type. */
      for(endct = p; *p && *p != ';' && *p != endchar; p++)
        if(!ISSPACE(*p))
          endct = p + 1;
      sep = *p;
    }
    else {
      /* unknown prefix, skip to next block */
      char *unknown = get_param_word(&p, &endpos, endchar);

      sep = *p;
      *endpos = '\0';
      if(*unknown)
        warnf(config->global, "skip unknown form field: %s\n", unknown);
    }
  }

  /* Terminate content type. */
  if(endct)
    *endct = '\0';

  if(ptype)
    *ptype = type;
  else if(type)
    warnf(config->global, "Field content type not allowed here: %s\n", type);

  if(pfilename)
    *pfilename = filename;
  else if(filename)
    warnf(config->global,
          "Field file name not allowed here: %s\n", filename);

  if(pencoder)
    *pencoder = encoder;
  else if(encoder)
    warnf(config->global,
          "Field encoder not allowed here: %s\n", encoder);

  if(pheaders)
    *pheaders = headers;
  else if(headers) {
    warnf(config->global,
          "Field headers not allowed here: %s\n", headers->data);
    curl_slist_free_all(headers);
  }

  *str = p;
  return sep & 0xFF;
}


/* Mime part callbacks for stdin. */
static size_t stdin_read(char *buffer, size_t size, size_t nitems, void *arg)
{
  standard_input *sip = (standard_input *) arg;
  curl_off_t bytesleft;
  (void) size;  /* Always 1: ignored. */

  if(sip->curpos >= sip->size)
    return 0;  /* At eof. */
  bytesleft = sip->size - sip->curpos;
  if((curl_off_t) nitems > bytesleft)
    nitems = (size_t) bytesleft;
  if(sip->data) {
    /* Return data from memory. */
    memcpy(buffer, sip->data + (size_t) sip->curpos, nitems);
  }
  else {
    /* Read from stdin. */
    nitems = fread(buffer, 1, nitems, stdin);
  }
  sip->curpos += nitems;
  return nitems;
}

static int stdin_seek(void *instream, curl_off_t offset, int whence)
{
  standard_input *sip = (standard_input *) instream;

  switch(whence) {
  case SEEK_CUR:
    offset += sip->curpos;
    break;
  case SEEK_END:
    offset += sip->size;
    break;
  }
  if(offset < 0)
    return CURL_SEEKFUNC_CANTSEEK;
  if(!sip->data) {
    if(fseek(stdin, (long) (offset + sip->origin), SEEK_SET))
      return CURL_SEEKFUNC_CANTSEEK;
  }
  sip->curpos = offset;
  return CURL_SEEKFUNC_OK;
}

static void stdin_free(void *ptr)
{
  standard_input *sip = (standard_input *) ptr;

  Curl_safefree(sip->data);
  free(sip);
}

/* Set a part's data from a file, taking care about the pseudo filename "-" as
 * a shortcut to read stdin: if so, use a callback to read OUR stdin (to
 * workaround Windows DLL file handle caveat).
 * If stdin is a regular file opened in binary mode, save current offset as
 * origin for rewind and do not buffer data. Else read to EOF and keep in
 * memory. In all cases, compute the stdin data size.
 */
static CURLcode file_or_stdin(curl_mimepart *part, const char *file)
{
  standard_input *sip = NULL;
  int fd = -1;
  CURLcode result = CURLE_OK;
  struct_stat sbuf;

  if(strcmp(file, "-"))
    return curl_mime_filedata(part, file);

  sip = (standard_input *) calloc(1, sizeof *sip);
  if(!sip)
    return CURLE_OUT_OF_MEMORY;

  set_binmode(stdin);

  /* If stdin is a regular file, do not buffer data but read it when needed. */
  fd = fileno(stdin);
  sip->origin = ftell(stdin);
  if(fd >= 0 && sip->origin >= 0 && !fstat(fd, &sbuf) &&
#ifdef __VMS
     sbuf.st_fab_rfm != FAB$C_VAR && sbuf.st_fab_rfm != FAB$C_VFC &&
#endif
     S_ISREG(sbuf.st_mode)) {
    sip->size = sbuf.st_size - sip->origin;
    if(sip->size < 0)
      sip->size = 0;
  }
  else {  /* Not suitable for direct use, buffer stdin data. */
    size_t stdinsize = 0;

    sip->origin = 0;
    if(file2memory(&sip->data, &stdinsize, stdin) != PARAM_OK)
      result = CURLE_OUT_OF_MEMORY;
    else {
      if(!stdinsize)
        sip->data = NULL;  /* Has been freed if no data. */
      sip->size = stdinsize;
      if(ferror(stdin))
        result = CURLE_READ_ERROR;
    }
  }

  /* Set remote file name. */
  if(!result)
    result = curl_mime_filename(part, file);

  /* Set part's data from callback. */
  if(!result)
    result = curl_mime_data_cb(part, sip->size,
                               stdin_read, stdin_seek, stdin_free, sip);
  if(result)
    stdin_free(sip);
  return result;
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
              curl_mime **mimepost,
              curl_mime **mimecurrent,
              bool literal_value)
{
  /* input MUST be a string in the format 'name=contents' and we'll
     build a linked list with the info */
  char *name = NULL;
  char *contents = NULL;
  char *contp;
  char *data;
  char *type = NULL;
  char *filename = NULL;
  char *encoder = NULL;
  struct curl_slist *headers = NULL;
  curl_mimepart *part = NULL;
  CURLcode res;
  int sep = '\0';

  /* Allocate the main mime structure if needed. */
  if(!*mimepost) {
    *mimepost = curl_mime_init(config->easy);
    if(!*mimepost) {
      warnf(config->global, "curl_mime_init failed!\n");
      return 1;
    }
    *mimecurrent = *mimepost;
  }

  /* Make a copy we can overwrite. */
  contents = strdup(input);
  if(!contents) {
    fprintf(config->global->errors, "out of memory\n");
    return 2;
  }

  /* Scan for the end of the name. */
  contp = strchr(contents, '=');
  if(contp) {
    if(contp > contents)
      name = contents;
    *contp++ = '\0';

    if(*contp == '(' && !literal_value) {
      curl_mime *subparts;

      /* Starting a multipart. */
      sep = get_param_part(config, '\0',
                           &contp, &data, &type, NULL, NULL, &headers);
      if(sep < 0) {
        Curl_safefree(contents);
        return 3;
      }
      subparts = curl_mime_init(config->easy);
      if(!subparts) {
        warnf(config->global, "curl_mime_init failed!\n");
        curl_slist_free_all(headers);
        Curl_safefree(contents);
        return 4;
      }
      part = curl_mime_addpart(*mimecurrent);
      if(!part) {
        warnf(config->global, "curl_mime_addpart failed!\n");
        curl_mime_free(subparts);
        curl_slist_free_all(headers);
        Curl_safefree(contents);
        return 5;
      }
      if(curl_mime_subparts(part, subparts)) {
        warnf(config->global, "curl_mime_subparts failed!\n");
        curl_mime_free(subparts);
        curl_slist_free_all(headers);
        Curl_safefree(contents);
        return 6;
      }
      *mimecurrent = subparts;
      if(curl_mime_headers(part, headers, 1)) {
        warnf(config->global, "curl_mime_headers failed!\n");
        curl_slist_free_all(headers);
        Curl_safefree(contents);
        return 7;
      }
      if(curl_mime_type(part, type)) {
        warnf(config->global, "curl_mime_type failed!\n");
        Curl_safefree(contents);
        return 8;
      }
    }
    else if(!name && !strcmp(contp, ")") && !literal_value) {
      /* Ending a mutipart. */
      if(*mimecurrent == *mimepost) {
        warnf(config->global, "no multipart to terminate!\n");
        Curl_safefree(contents);
        return 9;
        }
      *mimecurrent = (*mimecurrent)->parent->parent;
    }
    else if('@' == contp[0] && !literal_value) {

      /* we use the @-letter to indicate file name(s) */

      curl_mime *subparts = NULL;

      do {
        /* since this was a file, it may have a content-type specifier
           at the end too, or a filename. Or both. */
        ++contp;
        sep = get_param_part(config, ',', &contp,
                             &data, &type, &filename, &encoder, &headers);
        if(sep < 0) {
          if(subparts != *mimecurrent)
            curl_mime_free(subparts);
          Curl_safefree(contents);
          return 10;
        }

        /* now contp point to comma or string end.
           If more files to come, make sure we have multiparts. */
        if(!subparts) {
          if(sep != ',')    /* If there is a single file. */
            subparts = *mimecurrent;
          else {
            subparts = curl_mime_init(config->easy);
            if(!subparts) {
              warnf(config->global, "curl_mime_init failed!\n");
              curl_slist_free_all(headers);
              Curl_safefree(contents);
              return 11;
            }
          }
        }

        /* Allocate a part for that file. */
        part = curl_mime_addpart(subparts);
        if(!part) {
          warnf(config->global, "curl_mime_addpart failed!\n");
          if(subparts != *mimecurrent)
            curl_mime_free(subparts);
          curl_slist_free_all(headers);
          Curl_safefree(contents);
          return 12;
        }

        /* Set part headers. */
        if(curl_mime_headers(part, headers, 1)) {
          warnf(config->global, "curl_mime_headers failed!\n");
          if(subparts != *mimecurrent)
            curl_mime_free(subparts);
          curl_slist_free_all(headers);
          Curl_safefree(contents);
          return 13;
        }

        /* Setup file in part. */
        res = file_or_stdin(part, data);
        if(res) {
          warnf(config->global, "setting file %s  failed!\n", data);
          if(res != CURLE_READ_ERROR) {
            if(subparts != *mimecurrent)
              curl_mime_free(subparts);
            Curl_safefree(contents);
            return 14;
          }
        }
        if(filename && curl_mime_filename(part, filename)) {
          warnf(config->global, "curl_mime_filename failed!\n");
          if(subparts != *mimecurrent)
            curl_mime_free(subparts);
          Curl_safefree(contents);
          return 15;
        }
        if(curl_mime_type(part, type)) {
          warnf(config->global, "curl_mime_type failed!\n");
          if(subparts != *mimecurrent)
            curl_mime_free(subparts);
          Curl_safefree(contents);
          return 16;
        }
        if(curl_mime_encoder(part, encoder)) {
          warnf(config->global, "curl_mime_encoder failed!\n");
          if(subparts != *mimecurrent)
            curl_mime_free(subparts);
          Curl_safefree(contents);
          return 17;
        }

        /* *contp could be '\0', so we just check with the delimiter */
      } while(sep); /* loop if there's another file name */

      /* now we add the multiple files section */
      if(subparts != *mimecurrent) {
        part = curl_mime_addpart(*mimecurrent);
        if(!part) {
          warnf(config->global, "curl_mime_addpart failed!\n");
          curl_mime_free(subparts);
          Curl_safefree(contents);
          return 18;
        }
        if(curl_mime_subparts(part, subparts)) {
          warnf(config->global, "curl_mime_subparts failed!\n");
          curl_mime_free(subparts);
          Curl_safefree(contents);
          return 19;
        }
      }
    }
    else {
        /* Allocate a mime part. */
        part = curl_mime_addpart(*mimecurrent);
        if(!part) {
          warnf(config->global, "curl_mime_addpart failed!\n");
          Curl_safefree(contents);
          return 20;
        }

      if(*contp == '<' && !literal_value) {
        ++contp;
        sep = get_param_part(config, '\0', &contp,
                             &data, &type, NULL, &encoder, &headers);
        if(sep < 0) {
          Curl_safefree(contents);
          return 21;
        }

        /* Set part headers. */
        if(curl_mime_headers(part, headers, 1)) {
          warnf(config->global, "curl_mime_headers failed!\n");
          curl_slist_free_all(headers);
          Curl_safefree(contents);
          return 22;
        }

        /* Setup file in part. */
        res = file_or_stdin(part, data);
        if(res) {
          warnf(config->global, "setting file %s failed!\n", data);
          if(res != CURLE_READ_ERROR) {
            Curl_safefree(contents);
            return 23;
          }
        }
      }
      else {
        if(literal_value)
          data = contp;
        else {
          sep = get_param_part(config, '\0', &contp,
                               &data, &type, &filename, &encoder, &headers);
          if(sep < 0) {
            Curl_safefree(contents);
            return 24;
          }
        }

        /* Set part headers. */
        if(curl_mime_headers(part, headers, 1)) {
          warnf(config->global, "curl_mime_headers failed!\n");
          curl_slist_free_all(headers);
          Curl_safefree(contents);
          return 25;
        }

#ifdef CURL_DOES_CONVERSIONS
        if(convert_to_network(data, strlen(data))) {
          warnf(config->global, "curl_formadd failed!\n");
          Curl_safefree(contents);
          return 26;
        }
#endif

        if(curl_mime_data(part, data, CURL_ZERO_TERMINATED)) {
          warnf(config->global, "curl_mime_data failed!\n");
          Curl_safefree(contents);
          return 27;
        }
      }

      if(curl_mime_filename(part, filename)) {
        warnf(config->global, "curl_mime_filename failed!\n");
        Curl_safefree(contents);
        return 28;
      }
      if(curl_mime_type(part, type)) {
        warnf(config->global, "curl_mime_type failed!\n");
        Curl_safefree(contents);
        return 29;
      }
      if(curl_mime_encoder(part, encoder)) {
        warnf(config->global, "curl_mime_encoder failed!\n");
        Curl_safefree(contents);
        return 30;
      }

      if(sep) {
        *contp = (char) sep;
        warnf(config->global,
              "garbage at end of field specification: %s\n", contp);
      }
    }

    /* Set part name. */
    if(name && curl_mime_name(part, name)) {
      warnf(config->global, "curl_mime_name failed!\n");
      Curl_safefree(contents);
      return 31;
    }
  }
  else {
    warnf(config->global, "Illegally formatted input field!\n");
    Curl_safefree(contents);
    return 32;
  }
  Curl_safefree(contents);
  return 0;
}
