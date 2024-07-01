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

#include "strcase.h"

#define ENABLE_CURLX_PRINTF
/* use our own printf() functions */
#include "curlx.h"

#include "tool_cfgable.h"
#include "tool_msgs.h"
#include "tool_binmode.h"
#include "tool_getparam.h"
#include "tool_paramhlp.h"
#include "tool_formparse.h"

#include "memdebug.h" /* keep this as LAST include */

/* tool_mime functions. */
static struct tool_mime *tool_mime_new(struct tool_mime *parent,
                                       toolmimekind kind)
{
  struct tool_mime *m = (struct tool_mime *) calloc(1, sizeof(*m));

  if(m) {
    m->kind = kind;
    m->parent = parent;
    if(parent) {
      m->prev = parent->subparts;
      parent->subparts = m;
    }
  }
  return m;
}

static struct tool_mime *tool_mime_new_parts(struct tool_mime *parent)
{
  return tool_mime_new(parent, TOOLMIME_PARTS);
}

static struct tool_mime *tool_mime_new_data(struct tool_mime *parent,
                                            char *mime_data)
{
  char *mime_data_copy;
  struct tool_mime *m = NULL;

  mime_data_copy = strdup(mime_data);
  if(mime_data_copy) {
    m = tool_mime_new(parent, TOOLMIME_DATA);
    if(!m)
      free(mime_data_copy);
    else
      m->data = mime_data_copy;
  }
  return m;
}

static struct tool_mime *tool_mime_new_filedata(struct tool_mime *parent,
                                                const char *filename,
                                                bool isremotefile,
                                                CURLcode *errcode)
{
  CURLcode result = CURLE_OK;
  struct tool_mime *m = NULL;

  *errcode = CURLE_OUT_OF_MEMORY;
  if(strcmp(filename, "-")) {
    /* This is a normal file. */
    char *filedup = strdup(filename);
    if(filedup) {
      m = tool_mime_new(parent, TOOLMIME_FILE);
      if(!m)
        free(filedup);
      else {
        m->data = filedup;
        if(!isremotefile)
          m->kind = TOOLMIME_FILEDATA;
       *errcode = CURLE_OK;
      }
    }
  }
  else {        /* Standard input. */
    int fd = fileno(stdin);
    char *data = NULL;
    curl_off_t size;
    curl_off_t origin;
    struct_stat sbuf;

    set_binmode(stdin);
    origin = ftell(stdin);
    /* If stdin is a regular file, do not buffer data but read it
       when needed. */
    if(fd >= 0 && origin >= 0 && !fstat(fd, &sbuf) &&
#ifdef __VMS
       sbuf.st_fab_rfm != FAB$C_VAR && sbuf.st_fab_rfm != FAB$C_VFC &&
#endif
       S_ISREG(sbuf.st_mode)) {
      size = sbuf.st_size - origin;
      if(size < 0)
        size = 0;
    }
    else {  /* Not suitable for direct use, buffer stdin data. */
      size_t stdinsize = 0;

      switch(file2memory(&data, &stdinsize, stdin)) {
      case PARAM_NO_MEM:
        return m;
      case PARAM_READ_ERROR:
        result = CURLE_READ_ERROR;
        break;
      default:
        if(!stdinsize) {
          /* Zero-length data has been freed. Re-create it. */
          data = strdup("");
          if(!data)
            return m;
        }
        break;
      }
      size = curlx_uztoso(stdinsize);
      origin = 0;
    }
    m = tool_mime_new(parent, TOOLMIME_STDIN);
    if(!m)
      Curl_safefree(data);
    else {
      m->data = data;
      m->origin = origin;
      m->size = size;
      m->curpos = 0;
      if(!isremotefile)
        m->kind = TOOLMIME_STDINDATA;
      *errcode = result;
    }
  }
  return m;
}

void tool_mime_free(struct tool_mime *mime)
{
  if(mime) {
    if(mime->subparts)
      tool_mime_free(mime->subparts);
    if(mime->prev)
      tool_mime_free(mime->prev);
    Curl_safefree(mime->name);
    Curl_safefree(mime->filename);
    Curl_safefree(mime->type);
    Curl_safefree(mime->encoder);
    Curl_safefree(mime->data);
    curl_slist_free_all(mime->headers);
    free(mime);
  }
}


/* Mime part callbacks for stdin. */
size_t tool_mime_stdin_read(char *buffer,
                            size_t size, size_t nitems, void *arg)
{
  struct tool_mime *sip = (struct tool_mime *) arg;
  curl_off_t bytesleft;
  (void) size;  /* Always 1: ignored. */

  if(sip->size >= 0) {
    if(sip->curpos >= sip->size)
      return 0;  /* At eof. */
    bytesleft = sip->size - sip->curpos;
    if(curlx_uztoso(nitems) > bytesleft)
      nitems = curlx_sotouz(bytesleft);
  }
  if(nitems) {
    if(sip->data) {
      /* Return data from memory. */
      memcpy(buffer, sip->data + curlx_sotouz(sip->curpos), nitems);
    }
    else {
      /* Read from stdin. */
      nitems = fread(buffer, 1, nitems, stdin);
      if(ferror(stdin)) {
        /* Show error only once. */
        if(sip->config) {
          warnf(sip->config, "stdin: %s", strerror(errno));
          sip->config = NULL;
        }
        return CURL_READFUNC_ABORT;
      }
    }
    sip->curpos += curlx_uztoso(nitems);
  }
  return nitems;
}

int tool_mime_stdin_seek(void *instream, curl_off_t offset, int whence)
{
  struct tool_mime *sip = (struct tool_mime *) instream;

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

/* Translate an internal mime tree into a libcurl mime tree. */

static CURLcode tool2curlparts(CURL *curl, struct tool_mime *m,
                               curl_mime *mime)
{
  CURLcode ret = CURLE_OK;
  curl_mimepart *part = NULL;
  curl_mime *submime = NULL;
  const char *filename = NULL;

  if(m) {
    ret = tool2curlparts(curl, m->prev, mime);
    if(!ret) {
      part = curl_mime_addpart(mime);
      if(!part)
        ret = CURLE_OUT_OF_MEMORY;
    }
    if(!ret) {
      filename = m->filename;
      switch(m->kind) {
      case TOOLMIME_PARTS:
        ret = tool2curlmime(curl, m, &submime);
        if(!ret) {
          ret = curl_mime_subparts(part, submime);
          if(ret)
            curl_mime_free(submime);
        }
        break;

      case TOOLMIME_DATA:
        ret = curl_mime_data(part, m->data, CURL_ZERO_TERMINATED);
        break;

      case TOOLMIME_FILE:
      case TOOLMIME_FILEDATA:
        ret = curl_mime_filedata(part, m->data);
        if(!ret && m->kind == TOOLMIME_FILEDATA && !filename)
          ret = curl_mime_filename(part, NULL);
        break;

      case TOOLMIME_STDIN:
        if(!filename)
          filename = "-";
        FALLTHROUGH();
      case TOOLMIME_STDINDATA:
        ret = curl_mime_data_cb(part, m->size,
                                (curl_read_callback) tool_mime_stdin_read,
                                (curl_seek_callback) tool_mime_stdin_seek,
                                NULL, m);
        break;

      default:
        /* Other cases not possible in this context. */
        break;
      }
    }
    if(!ret && filename)
      ret = curl_mime_filename(part, filename);
    if(!ret)
      ret = curl_mime_type(part, m->type);
    if(!ret)
      ret = curl_mime_headers(part, m->headers, 0);
    if(!ret)
      ret = curl_mime_encoder(part, m->encoder);
    if(!ret)
      ret = curl_mime_name(part, m->name);
  }
  return ret;
}

CURLcode tool2curlmime(CURL *curl, struct tool_mime *m, curl_mime **mime)
{
  CURLcode ret = CURLE_OK;

  *mime = curl_mime_init(curl);
  if(!*mime)
    ret = CURLE_OUT_OF_MEMORY;
  else
    ret = tool2curlparts(curl, m->subparts, *mime);
  if(ret) {
    curl_mime_free(*mime);
    *mime = NULL;
  }
  return ret;
}

/*
 * helper function to get a word from form param
 * after call get_parm_word, str either point to string end
 * or point to any of end chars.
 */
static char *get_param_word(struct OperationConfig *config, char **str,
                            char **end_pos, char endchar)
{
  char *ptr = *str;
  /* the first non-space char is here */
  char *word_begin = ptr;
  char *ptr2;
  char *escape = NULL;

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
        bool trailing_data = FALSE;
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
        ++ptr;
        while(*ptr && *ptr != ';' && *ptr != endchar) {
          if(!ISSPACE(*ptr))
            trailing_data = TRUE;
          ++ptr;
        }
        if(trailing_data)
          warnf(config->global, "Trailing data after quoted form parameter");
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
  bool incomment = FALSE;
  int lineno = 1;
  char hdrbuf[999] = ""; /* Max. header length + 1. */

  for(;;) {
    int c = getc(fp);
    if(c == EOF || (!pos && !ISSPACE(c))) {
      /* Strip and flush the current header. */
      while(hdrlen && ISSPACE(hdrbuf[hdrlen - 1]))
        hdrlen--;
      if(hdrlen) {
        hdrbuf[hdrlen] = '\0';
        if(slist_append(pheaders, hdrbuf)) {
          errorf(config->global, "Out of memory for field headers");
          return -1;
        }
        hdrlen = 0;
      }
    }

    switch(c) {
    case EOF:
      if(ferror(fp)) {
        errorf(config->global, "Header file %s read error: %s", filename,
               strerror(errno));
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
      if(hdrlen == sizeof(hdrbuf) - 1) {
        warnf(config->global, "File %s line %d: header too long (truncated)",
              filename, lineno);
        c = ' ';
      }
      if(hdrlen <= sizeof(hdrbuf) - 1)
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
  *pdata = get_param_word(config, &p, &endpos, endchar);
  /* If not quoted, strip trailing spaces. */
  if(*pdata == tp)
    while(endpos > *pdata && ISSPACE(endpos[-1]))
      endpos--;
  sep = *p;
  *endpos = '\0';
  while(sep == ';') {
    while(p++ && ISSPACE(*p))
      ;

    if(!endct && checkprefix("type=", p)) {
      for(p += 5; ISSPACE(*p); p++)
        ;
      /* set type pointer */
      type = p;

      /* verify that this is a fine type specifier */
      if(2 != sscanf(type, "%127[^/ ]/%127[^;, \n]", type_major, type_minor)) {
        warnf(config->global, "Illegally formatted content-type field");
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
      filename = get_param_word(config, &p, &endpos, endchar);
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
        hdrfile = get_param_word(config, &p, &endpos, endchar);
        /* If not quoted, strip trailing spaces. */
        if(hdrfile == tp)
          while(endpos > hdrfile && ISSPACE(endpos[-1]))
            endpos--;
        sep = *p;
        *endpos = '\0';
        fp = fopen(hdrfile, FOPEN_READTEXT);
        if(!fp)
          warnf(config->global, "Cannot read from %s: %s", hdrfile,
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
        hdr = get_param_word(config, &p, &endpos, endchar);
        /* If not quoted, strip trailing spaces. */
        if(hdr == tp)
          while(endpos > hdr && ISSPACE(endpos[-1]))
            endpos--;
        sep = *p;
        *endpos = '\0';
        if(slist_append(&headers, hdr)) {
          errorf(config->global, "Out of memory for field header");
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
      encoder = get_param_word(config, &p, &endpos, endchar);
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
      char *unknown = get_param_word(config, &p, &endpos, endchar);

      sep = *p;
      *endpos = '\0';
      if(*unknown)
        warnf(config->global, "skip unknown form field: %s", unknown);
    }
  }

  /* Terminate content type. */
  if(endct)
    *endct = '\0';

  if(ptype)
    *ptype = type;
  else if(type)
    warnf(config->global, "Field content type not allowed here: %s", type);

  if(pfilename)
    *pfilename = filename;
  else if(filename)
    warnf(config->global,
          "Field filename not allowed here: %s", filename);

  if(pencoder)
    *pencoder = encoder;
  else if(encoder)
    warnf(config->global,
          "Field encoder not allowed here: %s", encoder);

  if(pheaders)
    *pheaders = headers;
  else if(headers) {
    warnf(config->global,
          "Field headers not allowed here: %s", headers->data);
    curl_slist_free_all(headers);
  }

  *str = p;
  return sep & 0xFF;
}


/***************************************************************************
 *
 * formparse()
 *
 * Reads a 'name=value' parameter and builds the appropriate linked list.
 *
 * If the value is of the form '<filename', field data is read from the
 * given file.

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
 * To upload a file, but to fake the filename that will be included in the
 * formpost, do like this:
 *
 * 'name=@filename;filename=/dev/null' or quote the faked filename like:
 * 'name=@filename;filename="play, play, and play.txt"'
 *
 * If filename/path contains ',' or ';', it must be quoted by double-quotes,
 * else curl will fail to figure out the correct filename. if the filename
 * tobe quoted contains '"' or '\', '"' and '\' must be escaped by backslash.
 *
 ***************************************************************************/

#define SET_TOOL_MIME_PTR(m, field)                                     \
  do {                                                                  \
    if(field) {                                                         \
      (m)->field = strdup(field);                                       \
      if(!(m)->field)                                                   \
        goto fail;                                                      \
    }                                                                   \
  } while(0)

int formparse(struct OperationConfig *config,
              const char *input,
              struct tool_mime **mimeroot,
              struct tool_mime **mimecurrent,
              bool literal_value)
{
  /* input MUST be a string in the format 'name=contents' and we will
     build a linked list with the info */
  char *name = NULL;
  char *contents = NULL;
  char *contp;
  char *data;
  char *type = NULL;
  char *filename = NULL;
  char *encoder = NULL;
  struct curl_slist *headers = NULL;
  struct tool_mime *part = NULL;
  CURLcode res;
  int err = 1;

  /* Allocate the main mime structure if needed. */
  if(!*mimecurrent) {
    *mimeroot = tool_mime_new_parts(NULL);
    if(!*mimeroot)
      goto fail;
    *mimecurrent = *mimeroot;
  }

  /* Make a copy we can overwrite. */
  contents = strdup(input);
  if(!contents)
    goto fail;

  /* Scan for the end of the name. */
  contp = strchr(contents, '=');
  if(contp) {
    int sep = '\0';
    if(contp > contents)
      name = contents;
    *contp++ = '\0';

    if(*contp == '(' && !literal_value) {
      /* Starting a multipart. */
      sep = get_param_part(config, '\0',
                           &contp, &data, &type, NULL, NULL, &headers);
      if(sep < 0)
        goto fail;
      part = tool_mime_new_parts(*mimecurrent);
      if(!part)
        goto fail;
      *mimecurrent = part;
      part->headers = headers;
      headers = NULL;
      SET_TOOL_MIME_PTR(part, type);
    }
    else if(!name && !strcmp(contp, ")") && !literal_value) {
      /* Ending a multipart. */
      if(*mimecurrent == *mimeroot) {
        warnf(config->global, "no multipart to terminate");
        goto fail;
      }
      *mimecurrent = (*mimecurrent)->parent;
    }
    else if('@' == contp[0] && !literal_value) {

      /* we use the @-letter to indicate filename(s) */

      struct tool_mime *subparts = NULL;

      do {
        /* since this was a file, it may have a content-type specifier
           at the end too, or a filename. Or both. */
        ++contp;
        sep = get_param_part(config, ',', &contp,
                             &data, &type, &filename, &encoder, &headers);
        if(sep < 0) {
          goto fail;
        }

        /* now contp point to comma or string end.
           If more files to come, make sure we have multiparts. */
        if(!subparts) {
          if(sep != ',')    /* If there is a single file. */
            subparts = *mimecurrent;
          else {
            subparts = tool_mime_new_parts(*mimecurrent);
            if(!subparts)
              goto fail;
          }
        }

        /* Store that file in a part. */
        part = tool_mime_new_filedata(subparts, data, TRUE, &res);
        if(!part)
          goto fail;
        part->headers = headers;
        headers = NULL;
        part->config = config->global;
        if(res == CURLE_READ_ERROR) {
            /* An error occurred while reading stdin: if read has started,
               issue the error now. Else, delay it until processed by
               libcurl. */
          if(part->size > 0) {
            warnf(config->global,
                  "error while reading standard input");
            goto fail;
          }
          Curl_safefree(part->data);
          part->data = NULL;
          part->size = -1;
          res = CURLE_OK;
        }
        SET_TOOL_MIME_PTR(part, filename);
        SET_TOOL_MIME_PTR(part, type);
        SET_TOOL_MIME_PTR(part, encoder);

        /* *contp could be '\0', so we just check with the delimiter */
      } while(sep); /* loop if there is another filename */
      part = (*mimecurrent)->subparts;  /* Set name on group. */
    }
    else {
      if(*contp == '<' && !literal_value) {
        ++contp;
        sep = get_param_part(config, '\0', &contp,
                             &data, &type, NULL, &encoder, &headers);
        if(sep < 0)
          goto fail;

        part = tool_mime_new_filedata(*mimecurrent, data, FALSE,
                                      &res);
        if(!part)
          goto fail;
        part->headers = headers;
        headers = NULL;
        part->config = config->global;
        if(res == CURLE_READ_ERROR) {
            /* An error occurred while reading stdin: if read has started,
               issue the error now. Else, delay it until processed by
               libcurl. */
          if(part->size > 0) {
            warnf(config->global,
                  "error while reading standard input");
            goto fail;
          }
          Curl_safefree(part->data);
          part->data = NULL;
          part->size = -1;
          res = CURLE_OK;
        }
      }
      else {
        if(literal_value)
          data = contp;
        else {
          sep = get_param_part(config, '\0', &contp,
                               &data, &type, &filename, &encoder, &headers);
          if(sep < 0)
            goto fail;
        }

        part = tool_mime_new_data(*mimecurrent, data);
        if(!part)
          goto fail;
        part->headers = headers;
        headers = NULL;
      }

      SET_TOOL_MIME_PTR(part, filename);
      SET_TOOL_MIME_PTR(part, type);
      SET_TOOL_MIME_PTR(part, encoder);

      if(sep) {
        *contp = (char) sep;
        warnf(config->global,
              "garbage at end of field specification: %s", contp);
      }
    }

    /* Set part name. */
    SET_TOOL_MIME_PTR(part, name);
  }
  else {
    warnf(config->global, "Illegally formatted input field");
    goto fail;
  }
  err = 0;
fail:
  Curl_safefree(contents);
  curl_slist_free_all(headers);
  return err;
}
