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
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include "curlx.h"

#include "tool_cfgable.h"
#include "tool_doswin.h"
#include "tool_msgs.h"
#include "tool_cb_hdr.h"
#include "tool_cb_wrt.h"
#include "tool_operate.h"
#include "tool_libinfo.h"

#include "memdebug.h" /* keep this as LAST include */

static char *parse_filename(const char *ptr, size_t len);

#ifdef _WIN32
#define BOLD "\x1b[1m"
#define BOLDOFF "\x1b[22m"
#else
#define BOLD "\x1b[1m"
/* Switch off bold by setting "all attributes off" since the explicit
   bold-off code (21) is not supported everywhere - like in the mac
   Terminal. */
#define BOLDOFF "\x1b[0m"
/* OSC 8 hyperlink escape sequence */
#define LINK "\x1b]8;;"
#define LINKST "\x1b\\"
#define LINKOFF LINK LINKST
#endif

#ifdef LINK
static void write_linked_location(CURL *curl, const char *location,
    size_t loclen, FILE *stream);
#endif

int tool_write_headers(struct HdrCbData *hdrcbdata, FILE *stream)
{
  struct curl_slist *h = hdrcbdata->headlist;
  int rc = 1;
  while(h) {
    /* not "handled", just show it */
    size_t len = strlen(h->data);
    if(len != fwrite(h->data, 1, len, stream))
      goto fail;
    h = h->next;
  }
  rc = 0; /* success */
fail:
  curl_slist_free_all(hdrcbdata->headlist);
  hdrcbdata->headlist = NULL;
  return rc;
}


/*
** callback for CURLOPT_HEADERFUNCTION
*/

size_t tool_header_cb(char *ptr, size_t size, size_t nmemb, void *userdata)
{
  struct per_transfer *per = userdata;
  struct HdrCbData *hdrcbdata = &per->hdrcbdata;
  struct OutStruct *outs = &per->outs;
  struct OutStruct *heads = &per->heads;
  struct OutStruct *etag_save = &per->etag_save;
  const char *str = ptr;
  const size_t cb = size * nmemb;
  const char *end = (char *)ptr + cb;
  const char *scheme = NULL;

  if(!per->config)
    return CURL_WRITEFUNC_ERROR;

#ifdef DEBUGBUILD
  if(size * nmemb > (size_t)CURL_MAX_HTTP_HEADER) {
    warnf(per->config->global, "Header data exceeds single call write limit");
    return CURL_WRITEFUNC_ERROR;
  }
#endif

#ifdef _WIN32
  /* Discard incomplete UTF-8 sequence buffered from body */
  if(outs->utf8seq[0])
    memset(outs->utf8seq, 0, sizeof(outs->utf8seq));
#endif

  /*
   * Write header data when curl option --dump-header (-D) is given.
   */

  if(per->config->headerfile && heads->stream) {
    size_t rc = fwrite(ptr, size, nmemb, heads->stream);
    if(rc != cb)
      return rc;
    /* flush the stream to send off what we got earlier */
    if(fflush(heads->stream)) {
      errorf(per->config->global, "Failed writing headers to %s",
             per->config->headerfile);
      return CURL_WRITEFUNC_ERROR;
    }
  }

  curl_easy_getinfo(per->curl, CURLINFO_SCHEME, &scheme);
  scheme = proto_token(scheme);
  if((scheme == proto_http || scheme == proto_https)) {
    long response = 0;
    curl_easy_getinfo(per->curl, CURLINFO_RESPONSE_CODE, &response);

    if((response/100 != 2) && (response/100 != 3))
      /* only care about etag and content-disposition headers in 2xx and 3xx
         responses */
      ;
    /*
     * Write etag to file when --etag-save option is given.
     */
    else if(per->config->etag_save_file && etag_save->stream &&
            /* match only header that start with etag (case insensitive) */
            checkprefix("etag:", str)) {
      const char *etag_h = &str[5];
      const char *eot = end - 1;
      if(*eot == '\n') {
        while(ISBLANK(*etag_h) && (etag_h < eot))
          etag_h++;
        while(ISSPACE(*eot))
          eot--;

        if(eot >= etag_h) {
          size_t etag_length = eot - etag_h + 1;
          /*
           * Truncate the etag save stream, it can have an existing etag value.
           */
#if defined(HAVE_FTRUNCATE) && !defined(__MINGW32CE__)
          if(ftruncate(fileno(etag_save->stream), 0)) {
            return CURL_WRITEFUNC_ERROR;
          }
#else
          if(fseek(etag_save->stream, 0, SEEK_SET)) {
            return CURL_WRITEFUNC_ERROR;
          }
#endif

          fwrite(etag_h, size, etag_length, etag_save->stream);
          /* terminate with newline */
          fputc('\n', etag_save->stream);
          (void)fflush(etag_save->stream);
        }
      }
    }

    /*
     * This callback sets the filename where output shall be written when
     * curl options --remote-name (-O) and --remote-header-name (-J) have
     * been simultaneously given and additionally server returns an HTTP
     * Content-Disposition header specifying a filename property.
     */

    else if(hdrcbdata->honor_cd_filename) {
      if((cb > 20) && checkprefix("Content-disposition:", str)) {
        const char *p = str + 20;

        /* look for the 'filename=' parameter
           (encoded filenames (*=) are not supported) */
        for(;;) {
          char *filename;
          size_t len;

          while((p < end) && *p && !ISALPHA(*p))
            p++;
          if(p > end - 9)
            break;

          if(memcmp(p, "filename=", 9)) {
            /* no match, find next parameter */
            while((p < end) && *p && (*p != ';'))
              p++;
            if((p < end) && *p)
              continue;
            else
              break;
          }
          p += 9;

          len = cb - (size_t)(p - str);
          filename = parse_filename(p, len);
          if(filename) {
            if(outs->stream) {
              /* indication of problem, get out! */
              FREE(filename);
              return CURL_WRITEFUNC_ERROR;
            }

            if(per->config->output_dir) {
              outs->filename = aprintf("%s/%s", per->config->output_dir,
                                       filename);
              FREE(filename);
              if(!outs->filename)
                return CURL_WRITEFUNC_ERROR;
            }
            else
              outs->filename = filename;

            outs->is_cd_filename = TRUE;
            outs->s_isreg = TRUE;
            outs->fopened = FALSE;
            outs->alloc_filename = TRUE;
            hdrcbdata->honor_cd_filename = FALSE; /* done now! */
            if(!tool_create_output_file(outs, per->config))
              return CURL_WRITEFUNC_ERROR;
            if(tool_write_headers(&per->hdrcbdata, outs->stream))
              return CURL_WRITEFUNC_ERROR;
          }
          break;
        }
        if(!outs->stream && !tool_create_output_file(outs, per->config))
          return CURL_WRITEFUNC_ERROR;
        if(tool_write_headers(&per->hdrcbdata, outs->stream))
          return CURL_WRITEFUNC_ERROR;
      } /* content-disposition handling */

      if(hdrcbdata->honor_cd_filename &&
         hdrcbdata->config->show_headers) {
        /* still awaiting the Content-Disposition header, store the header in
           memory. Since it is not zero terminated, we need an extra dance. */
        char *clone = aprintf("%.*s", (int)cb, str);
        if(clone) {
          struct curl_slist *old = hdrcbdata->headlist;
          hdrcbdata->headlist = curl_slist_append(old, clone);
          FREE(clone);
          if(!hdrcbdata->headlist) {
            curl_slist_free_all(old);
            return CURL_WRITEFUNC_ERROR;
          }
        }
        else {
          curl_slist_free_all(hdrcbdata->headlist);
          hdrcbdata->headlist = NULL;
          return CURL_WRITEFUNC_ERROR;
        }
        return cb; /* done for now */
      }
    }
  }
  if(hdrcbdata->config->writeout) {
    char *value = memchr(ptr, ':', cb);
    if(value) {
      if(per->was_last_header_empty)
        per->num_headers = 0;
      per->was_last_header_empty = FALSE;
      per->num_headers++;
    }
    else if(ptr[0] == '\r' || ptr[0] == '\n')
      per->was_last_header_empty = TRUE;
  }
  if(hdrcbdata->config->show_headers &&
    (scheme == proto_http || scheme == proto_https ||
     scheme == proto_rtsp || scheme == proto_file)) {
    /* bold headers only for selected protocols */
    char *value = NULL;

    if(!outs->stream && !tool_create_output_file(outs, per->config))
      return CURL_WRITEFUNC_ERROR;

    if(hdrcbdata->global->isatty &&
#ifdef _WIN32
       tool_term_has_bold &&
#endif
       hdrcbdata->global->styled_output)
      value = memchr(ptr, ':', cb);
    if(value) {
      size_t namelen = value - ptr;
      fprintf(outs->stream, BOLD "%.*s" BOLDOFF ":", (int)namelen, ptr);
#ifndef LINK
      fwrite(&value[1], cb - namelen - 1, 1, outs->stream);
#else
      if(curl_strnequal("Location", ptr, namelen)) {
        write_linked_location(per->curl, &value[1], cb - namelen - 1,
            outs->stream);
      }
      else
        fwrite(&value[1], cb - namelen - 1, 1, outs->stream);
#endif
    }
    else
      /* not "handled", just show it */
      fwrite(ptr, cb, 1, outs->stream);
  }
  return cb;
}

/*
 * Copies a filename part and returns an ALLOCATED data buffer.
 */
static char *parse_filename(const char *ptr, size_t len)
{
  char *copy;
  char *p;
  char *q;
  char  stop = '\0';

  /* simple implementation of strndup() */
  copy = MALLOC(len + 1);
  if(!copy)
    return NULL;
  memcpy(copy, ptr, len);
  copy[len] = '\0';

  p = copy;
  if(*p == '\'' || *p == '"') {
    /* store the starting quote */
    stop = *p;
    p++;
  }
  else
    stop = ';';

  /* scan for the end letter and stop there */
  q = strchr(p, stop);
  if(q)
    *q = '\0';

  /* if the filename contains a path, only use filename portion */
  q = strrchr(p, '/');
  if(q) {
    p = q + 1;
    if(!*p) {
      curlx_safefree(copy);
      return NULL;
    }
  }

  /* If the filename contains a backslash, only use filename portion. The idea
     is that even systems that do not handle backslashes as path separators
     probably want the path removed for convenience. */
  q = strrchr(p, '\\');
  if(q) {
    p = q + 1;
    if(!*p) {
      curlx_safefree(copy);
      return NULL;
    }
  }

  /* make sure the filename does not end in \r or \n */
  q = strchr(p, '\r');
  if(q)
    *q = '\0';

  q = strchr(p, '\n');
  if(q)
    *q = '\0';

  if(copy != p)
    memmove(copy, p, strlen(p) + 1);

#if defined(_WIN32) || defined(MSDOS)
  {
    char *sanitized;
    SANITIZEcode sc = sanitize_file_name(&sanitized, copy, 0);
    curlx_safefree(copy);
    if(sc)
      return NULL;
    copy = sanitized;
  }
#endif /* _WIN32 || MSDOS */

  return copy;
}

#ifdef LINK
/*
 * Treat the Location: header specially, by writing a special escape
 * sequence that adds a hyperlink to the displayed text. This makes
 * the absolute URL of the redirect clickable in supported terminals,
 * which could not happen otherwise for relative URLs. The Location:
 * header is supposed to always be absolute so this theoretically
 * should not be needed but the real world returns plenty of relative
 * URLs here.
 */
static
void write_linked_location(CURL *curl, const char *location, size_t loclen,
                           FILE *stream) {
  /* This would so simple if CURLINFO_REDIRECT_URL were available here */
  CURLU *u = NULL;
  char *copyloc = NULL, *locurl = NULL, *scheme = NULL, *finalurl = NULL;
  const char *loc = location;
  size_t llen = loclen;
  int space_skipped = 0;
  const char *vver = getenv("VTE_VERSION");

  if(vver) {
    curl_off_t num;
    if(curlx_str_number(&vver, &num, CURL_OFF_T_MAX) ||
       /* Skip formatting for old versions of VTE <= 0.48.1 (Mar 2017) since
          some of those versions have formatting bugs. (#10428) */
       (num <= 4801))
      goto locout;
  }

  /* Strip leading whitespace of the redirect URL */
  while(llen && (*loc == ' ' || *loc == '\t')) {
    ++loc;
    --llen;
    ++space_skipped;
  }

  /* Strip the trailing end-of-line characters, normally "\r\n" */
  while(llen && (loc[llen-1] == '\n' || loc[llen-1] == '\r'))
    --llen;

  /* CURLU makes it easy to handle the relative URL case */
  u = curl_url();
  if(!u)
    goto locout;

  /* Create a NUL-terminated and whitespace-stripped copy of Location: */
  copyloc = MALLOC(llen + 1);
  if(!copyloc)
    goto locout;
  memcpy(copyloc, loc, llen);
  copyloc[llen] = 0;

  /* The original URL to use as a base for a relative redirect URL */
  if(curl_easy_getinfo(curl, CURLINFO_EFFECTIVE_URL, &locurl))
    goto locout;
  if(curl_url_set(u, CURLUPART_URL, locurl, 0))
    goto locout;

  /* Redirected location. This can be either absolute or relative. */
  if(curl_url_set(u, CURLUPART_URL, copyloc, 0))
    goto locout;

  if(curl_url_get(u, CURLUPART_URL, &finalurl, CURLU_NO_DEFAULT_PORT))
    goto locout;

  if(curl_url_get(u, CURLUPART_SCHEME, &scheme, 0))
    goto locout;

  if(!strcmp("http", scheme) ||
     !strcmp("https", scheme) ||
     !strcmp("ftp", scheme) ||
     !strcmp("ftps", scheme)) {
    fprintf(stream, "%.*s" LINK "%s" LINKST "%.*s" LINKOFF,
            space_skipped, location,
            finalurl,
            (int)loclen - space_skipped, loc);
    goto locdone;
  }

  /* Not a "safe" URL: do not linkify it */

locout:
  /* Write the normal output in case of error or unsafe */
  fwrite(location, loclen, 1, stream);

locdone:
  if(u) {
    curl_free(finalurl);
    curl_free(scheme);
    curl_url_cleanup(u);
    FREE(copyloc);
  }
}
#endif
