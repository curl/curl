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

#ifdef HAVE_FCNTL_H
#  include <fcntl.h>
#endif

#ifdef HAVE_LOCALE_H
#  include <locale.h>
#endif

#ifdef HAVE_SYS_SELECT_H
#  include <sys/select.h>
#elif defined(HAVE_UNISTD_H)
#  include <unistd.h>
#endif

#ifdef __VMS
#  include <fabdef.h>
#endif

#ifdef __AMIGA__
#  include <proto/dos.h>
#endif

#ifdef HAVE_NETINET_IN_H
#  include <netinet/in.h>
#endif

#ifdef HAVE_UV_H
/* this is for libuv-enabled debug builds only */
#include <uv.h>
#endif

#include "tool_cfgable.h"
#include "tool_cb_dbg.h"
#include "tool_cb_hdr.h"
#include "tool_cb_prg.h"
#include "tool_cb_rea.h"
#include "tool_cb_see.h"
#include "tool_cb_soc.h"
#include "tool_cb_wrt.h"
#include "tool_dirhie.h"
#include "tool_doswin.h"
#include "tool_easysrc.h"
#include "tool_filetime.h"
#include "tool_getparam.h"
#include "tool_helpers.h"
#include "tool_findfile.h"
#include "tool_libinfo.h"
#include "tool_main.h"
#include "tool_msgs.h"
#include "tool_operate.h"
#include "tool_operhlp.h"
#include "tool_paramhlp.h"
#include "tool_parsecfg.h"
#include "tool_setopt.h"
#include "tool_ssls.h"
#include "tool_urlglob.h"
#include "tool_util.h"
#include "tool_writeout.h"
#include "tool_xattr.h"
#include "tool_vms.h"
#include "tool_help.h"
#include "tool_hugehelp.h"
#include "tool_progress.h"
#include "tool_ipfs.h"
#include "config2setopts.h"

#ifdef DEBUGBUILD
/* libcurl's debug-only curl_easy_perform_ev() */
CURL_EXTERN CURLcode curl_easy_perform_ev(CURL *easy);
#endif

#include "memdebug.h" /* keep this as LAST include */

#ifdef CURL_CA_EMBED
#ifndef CURL_DECLARED_CURL_CA_EMBED
#define CURL_DECLARED_CURL_CA_EMBED
extern const unsigned char curl_ca_embed[];
#endif
#endif

#define CURL_CA_CERT_ERRORMSG                                              \
  "More details here: https://curl.se/docs/sslcerts.html\n\n"              \
  "curl failed to verify the legitimacy of the server and therefore "      \
  "could not\nestablish a secure connection to it. To learn more about "   \
  "this situation and\nhow to fix it, please visit the webpage mentioned " \
  "above.\n"

static CURLcode create_transfer(CURLSH *share,
                                bool *added,
                                bool *skipped);

static bool is_fatal_error(CURLcode code)
{
  switch(code) {
  case CURLE_FAILED_INIT:
  case CURLE_OUT_OF_MEMORY:
  case CURLE_UNKNOWN_OPTION:
  case CURLE_BAD_FUNCTION_ARGUMENT:
    /* critical error */
    return TRUE;
  default:
    break;
  }

  /* no error or not critical */
  return FALSE;
}

/*
 * Check if a given string is a PKCS#11 URI
 */
static bool is_pkcs11_uri(const char *string)
{
  if(curl_strnequal(string, "pkcs11:", 7)) {
    return TRUE;
  }
  else {
    return FALSE;
  }
}

#ifdef __VMS
/*
 * get_vms_file_size does what it takes to get the real size of the file
 *
 * For fixed files, find out the size of the EOF block and adjust.
 *
 * For all others, have to read the entire file in, discarding the contents.
 * Most posted text files will be small, and binary files like zlib archives
 * and CD/DVD images should be either a STREAM_LF format or a fixed format.
 *
 */
static curl_off_t vms_realfilesize(const char *name,
                                   const struct_stat *stat_buf)
{
  char buffer[8192];
  curl_off_t count;
  int ret_stat;
  FILE * file;

  /* !checksrc! disable FOPENMODE 1 */
  file = fopen(name, "r"); /* VMS */
  if(!file) {
    return 0;
  }
  count = 0;
  ret_stat = 1;
  while(ret_stat > 0) {
    ret_stat = fread(buffer, 1, sizeof(buffer), file);
    if(ret_stat)
      count += ret_stat;
  }
  fclose(file);

  return count;
}

/*
 *
 *  VmsSpecialSize checks to see if the stat st_size can be trusted and
 *  if not to call a routine to get the correct size.
 *
 */
static curl_off_t VmsSpecialSize(const char *name,
                                 const struct_stat *stat_buf)
{
  switch(stat_buf->st_fab_rfm) {
  case FAB$C_VAR:
  case FAB$C_VFC:
    return vms_realfilesize(name, stat_buf);
    break;
  default:
    return stat_buf->st_size;
  }
}
#endif /* __VMS */

struct per_transfer *transfers; /* first node */
static struct per_transfer *transfersl; /* last node */

/* add_per_transfer creates a new 'per_transfer' node in the linked
   list of transfers */
static CURLcode add_per_transfer(struct per_transfer **per)
{
  struct per_transfer *p;
  p = calloc(1, sizeof(struct per_transfer));
  if(!p)
    return CURLE_OUT_OF_MEMORY;
  if(!transfers)
    /* first entry */
    transfersl = transfers = p;
  else {
    /* make the last node point to the new node */
    transfersl->next = p;
    /* make the new node point back to the formerly last node */
    p->prev = transfersl;
    /* move the last node pointer to the new entry */
    transfersl = p;
  }
  *per = p;

  return CURLE_OK;
}

/* Remove the specified transfer from the list (and free it), return the next
   in line */
static struct per_transfer *del_per_transfer(struct per_transfer *per)
{
  struct per_transfer *n;
  struct per_transfer *p;
  DEBUGASSERT(transfers);
  DEBUGASSERT(transfersl);
  DEBUGASSERT(per);

  n = per->next;
  p = per->prev;

  if(p)
    p->next = n;
  else
    transfers = n;

  if(n)
    n->prev = p;
  else
    transfersl = p;

  free(per);

  return n;
}

static CURLcode pre_transfer(struct per_transfer *per)
{
  curl_off_t uploadfilesize = -1;
  struct_stat fileinfo;
  CURLcode result = CURLE_OK;

  if(per->uploadfile && !stdin_upload(per->uploadfile)) {
    /* VMS Note:
     *
     * Reading binary from files can be a problem... Only FIXED, VAR
     * etc WITHOUT implied CC will work. Others need a \n appended to
     * a line
     *
     * - Stat gives a size but this is UNRELIABLE in VMS. E.g.
     * a fixed file with implied CC needs to have a byte added for every
     * record processed, this can be derived from Filesize & recordsize
     * for VARiable record files the records need to be counted!  for
     * every record add 1 for linefeed and subtract 2 for the record
     * header for VARIABLE header files only the bare record data needs
     * to be considered with one appended if implied CC
     */
#ifdef __VMS
    /* Calculate the real upload size for VMS */
    per->infd = -1;
    if(stat(per->uploadfile, &fileinfo) == 0) {
      fileinfo.st_size = VmsSpecialSize(uploadfile, &fileinfo);
      switch(fileinfo.st_fab_rfm) {
      case FAB$C_VAR:
      case FAB$C_VFC:
      case FAB$C_STMCR:
        per->infd = open(per->uploadfile, O_RDONLY | CURL_O_BINARY);
        break;
      default:
        per->infd = open(per->uploadfile, O_RDONLY | CURL_O_BINARY,
                         "rfm=stmlf", "ctx=stm");
      }
    }
    if(per->infd == -1)
#else
      per->infd = open(per->uploadfile, O_RDONLY | CURL_O_BINARY);
    if((per->infd == -1) || fstat(per->infd, &fileinfo))
#endif
    {
      helpf("cannot open '%s'", per->uploadfile);
      if(per->infd != -1) {
        close(per->infd);
        per->infd = STDIN_FILENO;
      }
      return CURLE_READ_ERROR;
    }
    per->infdopen = TRUE;

    /* we ignore file size for char/block devices, sockets, etc. */
    if(S_ISREG(fileinfo.st_mode))
      uploadfilesize = fileinfo.st_size;

#ifdef DEBUGBUILD
    /* allow dedicated test cases to override */
    {
      char *ev = getenv("CURL_UPLOAD_SIZE");
      if(ev) {
        int sz = atoi(ev);
        uploadfilesize = (curl_off_t)sz;
      }
    }
#endif

    if(uploadfilesize != -1)
      my_setopt_offt(per->curl, CURLOPT_INFILESIZE_LARGE, uploadfilesize);
  }
  per->uploadfilesize = uploadfilesize;
  per->start = curlx_now();
  return result;
}

void single_transfer_cleanup(void)
{
  struct State *state = &global->state;
  /* Free list of remaining URLs */
  glob_cleanup(&state->urlglob);
  tool_safefree(state->uploadfile);
  /* Free list of globbed upload files */
  glob_cleanup(&state->inglob);
}

static CURLcode retrycheck(struct OperationConfig *config,
                           struct per_transfer *per,
                           CURLcode result,
                           bool *retryp,
                           long *delayms)
{
  CURL *curl = per->curl;
  struct OutStruct *outs = &per->outs;
  enum {
    RETRY_NO,
    RETRY_ALL_ERRORS,
    RETRY_TIMEOUT,
    RETRY_CONNREFUSED,
    RETRY_HTTP,
    RETRY_FTP,
    RETRY_LAST /* not used */
  } retry = RETRY_NO;
  long response = 0;
  if((CURLE_OPERATION_TIMEDOUT == result) ||
     (CURLE_COULDNT_RESOLVE_HOST == result) ||
     (CURLE_COULDNT_RESOLVE_PROXY == result) ||
     (CURLE_FTP_ACCEPT_TIMEOUT == result))
    /* retry timeout always */
    retry = RETRY_TIMEOUT;
  else if(config->retry_connrefused &&
          (CURLE_COULDNT_CONNECT == result)) {
    long oserrno = 0;
    curl_easy_getinfo(curl, CURLINFO_OS_ERRNO, &oserrno);
    if(SOCKECONNREFUSED == oserrno)
      retry = RETRY_CONNREFUSED;
  }
  else if((CURLE_OK == result) ||
          ((config->failonerror || config->failwithbody) &&
           (CURLE_HTTP_RETURNED_ERROR == result))) {
    /* If it returned OK. _or_ failonerror was enabled and it
       returned due to such an error, check for HTTP transient
       errors to retry on. */
    const char *scheme;
    curl_easy_getinfo(curl, CURLINFO_SCHEME, &scheme);
    scheme = proto_token(scheme);
    if(scheme == proto_http || scheme == proto_https) {
      /* This was HTTP(S) */
      curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response);

      switch(response) {
      case 408: /* Request Timeout */
      case 429: /* Too Many Requests (RFC6585) */
      case 500: /* Internal Server Error */
      case 502: /* Bad Gateway */
      case 503: /* Service Unavailable */
      case 504: /* Gateway Timeout */
        retry = RETRY_HTTP;
        /*
         * At this point, we have already written data to the output
         * file (or terminal). If we write to a file, we must rewind
         * or close/re-open the file so that the next attempt starts
         * over from the beginning.
         *
         * For the upload case, we might need to start over reading from a
         * previous point if we have uploaded something when this was
         * returned.
         */
        break;
      }
    }
  } /* if CURLE_OK */
  else if(result) {
    const char *scheme;

    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response);
    curl_easy_getinfo(curl, CURLINFO_SCHEME, &scheme);
    scheme = proto_token(scheme);

    if((scheme == proto_ftp || scheme == proto_ftps) && response / 100 == 4)
      /*
       * This is typically when the FTP server only allows a certain
       * amount of users and we are not one of them. All 4xx codes
       * are transient.
       */
      retry = RETRY_FTP;
  }

  if(result && !retry && config->retry_all_errors)
    retry = RETRY_ALL_ERRORS;

  if(retry) {
    long sleeptime = 0;
    curl_off_t retry_after = 0;
    static const char * const m[]={
      NULL,
      "(retrying all errors)",
      ": timeout",
      ": connection refused",
      ": HTTP error",
      ": FTP error"
    };

    sleeptime = per->retry_sleep;
    if(RETRY_HTTP == retry) {
      curl_easy_getinfo(curl, CURLINFO_RETRY_AFTER, &retry_after);
      if(retry_after) {
        /* store in a 'long', make sure it does not overflow */
        if(retry_after > LONG_MAX/1000)
          sleeptime = LONG_MAX;
        else if((retry_after * 1000) > sleeptime)
          sleeptime = (long)retry_after * 1000; /* milliseconds */

        /* if adding retry_after seconds to the process would exceed the
           maximum time allowed for retrying, then exit the retries right
           away */
        if(config->retry_maxtime_ms) {
          timediff_t ms = curlx_timediff(curlx_now(), per->retrystart);

          if((CURL_OFF_T_MAX - sleeptime < ms) ||
             (ms + sleeptime > config->retry_maxtime_ms)) {
            warnf("The Retry-After: time would "
                  "make this command line exceed the maximum allowed time "
                  "for retries.");
            *retryp = FALSE;
            return CURLE_OK; /* no retry */
          }
        }
      }
    }
    warnf("Problem %s. "
          "Will retry in %ld second%s. "
          "%ld retr%s left.",
          m[retry], sleeptime/1000L,
          (sleeptime/1000L == 1 ? "" : "s"),
          per->retry_remaining,
          (per->retry_remaining > 1 ? "ies" : "y"));

    per->retry_remaining--;
    if(!config->retry_delay_ms) {
      per->retry_sleep *= 2;
      if(per->retry_sleep > RETRY_SLEEP_MAX)
        per->retry_sleep = RETRY_SLEEP_MAX;
    }

    if(outs->bytes && outs->filename && outs->stream) {
#ifndef __MINGW32CE__
      struct_stat fileinfo;

      /* The output can be a named pipe or a character device etc that
         cannot be truncated. Only truncate regular files. */
      if(!fstat(fileno(outs->stream), &fileinfo) &&
         S_ISREG(fileinfo.st_mode))
#else
        /* Windows CE's fileno() is bad so just skip the check */
#endif
      {
        int rc;
        /* We have written data to an output file, we truncate file */
        fflush(outs->stream);
        notef("Throwing away %"  CURL_FORMAT_CURL_OFF_T " bytes",
              outs->bytes);
        /* truncate file at the position where we started appending */
#if defined(HAVE_FTRUNCATE) && !defined(__DJGPP__) && !defined(__AMIGA__) && \
  !defined(__MINGW32CE__)
        if(ftruncate(fileno(outs->stream), outs->init)) {
          /* when truncate fails, we cannot just append as then we will
             create something strange, bail out */
          errorf("Failed to truncate file");
          return CURLE_WRITE_ERROR;
        }
        /* now seek to the end of the file, the position where we
           just truncated the file in a large file-safe way */
        rc = fseek(outs->stream, 0, SEEK_END);
#else
        /* ftruncate is not available, so just reposition the file
           to the location we would have truncated it. This will not
           work properly with large files on 32-bit systems, but
           most of those will have ftruncate. */
        rc = fseek(outs->stream, (long)outs->init, SEEK_SET);
#endif
        if(rc) {
          errorf("Failed seeking to end of file");
          return CURLE_WRITE_ERROR;
        }
        outs->bytes = 0; /* clear for next round */
      }
    }
    *retryp = TRUE;
    per->num_retries++;
    *delayms = sleeptime;
    result = CURLE_OK;
  }
  return result;
}


/*
 * Call this after a transfer has completed.
 */
static CURLcode post_per_transfer(struct per_transfer *per,
                                  CURLcode result,
                                  bool *retryp,
                                  long *delay) /* milliseconds! */
{
  struct OutStruct *outs = &per->outs;
  CURL *curl = per->curl;
  struct OperationConfig *config = per->config;
  int rc;

  *retryp = FALSE;
  *delay = 0; /* for no retry, keep it zero */

  if(!curl || !config)
    return result;

  if(per->uploadfile) {
    if(!strcmp(per->uploadfile, ".") && per->infd > 0) {
#if defined(_WIN32) && !defined(CURL_WINDOWS_UWP) && !defined(UNDER_CE)
      sclose(per->infd);
#else
      warnf("Closing per->infd != 0: FD == "
            "%d. This behavior is only supported on desktop "
            " Windows", per->infd);
#endif
    }
  }
  else {
    if(per->infdopen) {
      close(per->infd);
    }
  }

  if(per->skip)
    goto skip;

#ifdef __VMS
  if(is_vms_shell()) {
    /* VMS DCL shell behavior */
    if(global->silent && !global->showerror)
      vms_show = VMSSTS_HIDE;
  }
  else
#endif
    if(!config->synthetic_error && result &&
       (!global->silent || global->showerror)) {
      const char *msg = per->errorbuffer;
      fprintf(tool_stderr, "curl: (%d) %s\n", result,
              msg[0] ? msg : curl_easy_strerror(result));
      if(result == CURLE_PEER_FAILED_VERIFICATION)
        fputs(CURL_CA_CERT_ERRORMSG, tool_stderr);
    }
    else if(config->failwithbody) {
      /* if HTTP response >= 400, return error */
      long code = 0;
      curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &code);
      if(code >= 400) {
        if(!global->silent || global->showerror)
          fprintf(tool_stderr,
                  "curl: (%d) The requested URL returned error: %ld\n",
                  CURLE_HTTP_RETURNED_ERROR, code);
        result = CURLE_HTTP_RETURNED_ERROR;
      }
    }
  /* Set file extended attributes */
  if(!result && config->xattr && outs->fopened && outs->stream) {
    rc = fwrite_xattr(curl, per->url, fileno(outs->stream));
    if(rc)
      warnf("Error setting extended attributes on '%s': %s",
            outs->filename, strerror(errno));
  }

  if(!result && !outs->stream && !outs->bytes) {
    /* we have received no data despite the transfer was successful
       ==> force creation of an empty output file (if an output file
       was specified) */
    long cond_unmet = 0L;
    /* do not create (or even overwrite) the file in case we get no
       data because of unmet condition */
    curl_easy_getinfo(curl, CURLINFO_CONDITION_UNMET, &cond_unmet);
    if(!cond_unmet && !tool_create_output_file(outs, config))
      result = CURLE_WRITE_ERROR;
  }

  if(!outs->s_isreg && outs->stream) {
    /* Dump standard stream buffered data */
    rc = fflush(outs->stream);
    if(!result && rc) {
      /* something went wrong in the writing process */
      result = CURLE_WRITE_ERROR;
      errorf("Failed writing body");
    }
  }

#ifdef _WIN32
  /* Discard incomplete UTF-8 sequence buffered from body */
  if(outs->utf8seq[0])
    memset(outs->utf8seq, 0, sizeof(outs->utf8seq));
#endif

  /* if retry-max-time is non-zero, make sure we have not exceeded the
     time */
  if(per->retry_remaining &&
     (!config->retry_maxtime_ms ||
      (curlx_timediff(curlx_now(), per->retrystart) <
       config->retry_maxtime_ms)) ) {
    result = retrycheck(config, per, result, retryp, delay);
    if(!result && *retryp)
      return CURLE_OK; /* retry! */
  }

  if((global->progressmode == CURL_PROGRESS_BAR) &&
     per->progressbar.calls)
    /* if the custom progress bar has been displayed, we output a
       newline here */
    fputs("\n", per->progressbar.out);

  /* Close the outs file */
  if(outs->fopened && outs->stream) {
    rc = fclose(outs->stream);
    if(!result && rc) {
      /* something went wrong in the writing process */
      result = CURLE_WRITE_ERROR;
      errorf("curl: (%d) Failed writing body", result);
    }
    if(result && config->rm_partial) {
      struct_stat st;
      if(!stat(outs->filename, &st) &&
         S_ISREG(st.st_mode)) {
        if(!unlink(outs->filename))
          notef("Removed output file: %s", outs->filename);
        else
          warnf("Failed removing: %s", outs->filename);
      }
      else
        warnf("Skipping removal; not a regular file: %s",
              outs->filename);
    }
  }

  /* File time can only be set _after_ the file has been closed */
  if(!result && config->remote_time && outs->s_isreg && outs->filename) {
    /* Ask libcurl if we got a remote file time */
    curl_off_t filetime = -1;
    curl_easy_getinfo(curl, CURLINFO_FILETIME_T, &filetime);
    if(filetime != -1)
      setfiletime(filetime, outs->filename);
  }
skip:
  /* Write the --write-out data before cleanup but after result is final */
  if(config->writeout)
    ourWriteOut(config, per, result);

  /* Close function-local opened file descriptors */
  if(per->heads.fopened && per->heads.stream)
    fclose(per->heads.stream);

  if(per->heads.alloc_filename)
    tool_safefree(per->heads.filename);

  if(per->etag_save.fopened && per->etag_save.stream)
    fclose(per->etag_save.stream);

  if(per->etag_save.alloc_filename)
    tool_safefree(per->etag_save.filename);

  curl_easy_cleanup(per->curl);
  if(outs->alloc_filename)
    free(outs->filename);
  free(per->url);
  free(per->outfile);
  free(per->uploadfile);
  curl_slist_free_all(per->hdrcbdata.headlist);
  per->hdrcbdata.headlist = NULL;
  return result;
}

static CURLcode set_cert_types(struct OperationConfig *config)
{
  if(feature_ssl) {
    /* Check if config->cert is a PKCS#11 URI and set the config->cert_type if
     * necessary */
    if(config->cert && !config->cert_type && is_pkcs11_uri(config->cert)) {
      config->cert_type = strdup("ENG");
      if(!config->cert_type)
        return CURLE_OUT_OF_MEMORY;
    }

    /* Check if config->key is a PKCS#11 URI and set the config->key_type if
     * necessary */
    if(config->key && !config->key_type && is_pkcs11_uri(config->key)) {
      config->key_type = strdup("ENG");
      if(!config->key_type)
        return CURLE_OUT_OF_MEMORY;
    }

    /* Check if config->proxy_cert is a PKCS#11 URI and set the
     * config->proxy_type if necessary */
    if(config->proxy_cert && !config->proxy_cert_type &&
       is_pkcs11_uri(config->proxy_cert)) {
      config->proxy_cert_type = strdup("ENG");
      if(!config->proxy_cert_type)
        return CURLE_OUT_OF_MEMORY;
    }

    /* Check if config->proxy_key is a PKCS#11 URI and set the
     * config->proxy_key_type if necessary */
    if(config->proxy_key && !config->proxy_key_type &&
       is_pkcs11_uri(config->proxy_key)) {
      config->proxy_key_type = strdup("ENG");
      if(!config->proxy_key_type)
        return CURLE_OUT_OF_MEMORY;
    }
  }
  return CURLE_OK;
}

static CURLcode append2query(struct OperationConfig *config,
                             struct per_transfer *per,
                             const char *q)
{
  CURLcode result = CURLE_OK;
  CURLU *uh = curl_url();
  if(uh) {
    CURLUcode uerr;
    uerr = curl_url_set(uh, CURLUPART_URL, per->url,
                        CURLU_GUESS_SCHEME);
    if(uerr) {
      result = urlerr_cvt(uerr);
      errorf("(%d) Could not parse the URL, "
             "failed to set query", result);
      config->synthetic_error = TRUE;
    }
    else {
      char *updated = NULL;
      uerr = curl_url_set(uh, CURLUPART_QUERY, q, CURLU_APPENDQUERY);
      if(!uerr)
        uerr = curl_url_get(uh, CURLUPART_URL, &updated,
                            CURLU_GUESS_SCHEME);
      if(uerr)
        result = urlerr_cvt(uerr);
      else {
        free(per->url); /* free previous URL */
        per->url = updated; /* use our new URL instead! */
      }
    }
    curl_url_cleanup(uh);
  }
  return result;
}

static CURLcode etag_compare(struct OperationConfig *config)
{
  CURLcode result = CURLE_OK;
  char *etag_from_file = NULL;
  char *header = NULL;
  ParameterError pe;

  /* open file for reading: */
  FILE *file = fopen(config->etag_compare_file, FOPEN_READTEXT);
  if(!file)
    warnf("Failed to open %s: %s", config->etag_compare_file,
          strerror(errno));

  if((PARAM_OK == file2string(&etag_from_file, file)) &&
     etag_from_file) {
    header = aprintf("If-None-Match: %s", etag_from_file);
    tool_safefree(etag_from_file);
  }
  else
    header = aprintf("If-None-Match: \"\"");

  if(!header) {
    if(file)
      fclose(file);
    errorf("Failed to allocate memory for custom etag header");
    return CURLE_OUT_OF_MEMORY;
  }

  /* add Etag from file to list of custom headers */
  pe = add2list(&config->headers, header);
  tool_safefree(header);

  if(file)
    fclose(file);
  if(pe != PARAM_OK)
    result = CURLE_OUT_OF_MEMORY;
  return result;
}

static CURLcode etag_store(struct OperationConfig *config,
                           struct OutStruct *etag_save,
                           bool *skip)
{
  if(config->create_dirs) {
    CURLcode result = create_dir_hierarchy(config->etag_save_file);
    if(result)
      return result;
  }

  /* open file for output: */
  if(strcmp(config->etag_save_file, "-")) {
    FILE *newfile = fopen(config->etag_save_file, "ab");
    if(!newfile) {
      warnf("Failed creating file for saving etags: \"%s\". "
            "Skip this transfer", config->etag_save_file);
      *skip = TRUE;
      return CURLE_OK;
    }
    else {
      etag_save->filename = config->etag_save_file;
      etag_save->s_isreg = TRUE;
      etag_save->fopened = TRUE;
      etag_save->stream = newfile;
    }
  }
  else {
    /* always use binary mode for protocol header output */
    CURLX_SET_BINMODE(etag_save->stream);
  }
  return CURLE_OK;
}

static CURLcode setup_headerfile(struct OperationConfig *config,
                                 struct per_transfer *per,
                                 struct OutStruct *heads)
{
  /* open file for output: */
  if(!strcmp(config->headerfile, "%")) {
    heads->stream = stderr;
    /* use binary mode for protocol header output */
    CURLX_SET_BINMODE(heads->stream);
  }
  else if(strcmp(config->headerfile, "-")) {
    FILE *newfile;

    /*
     * Since every transfer has its own file handle for dumping
     * the headers, we need to open it in append mode, since transfers
     * might finish in any order.
     * The first transfer just clears the file.
     *
     * Consider placing the file handle inside the OperationConfig, so
     * that it does not need to be opened/closed for every transfer.
     */
    if(config->create_dirs) {
      CURLcode result = create_dir_hierarchy(config->headerfile);
      /* create_dir_hierarchy shows error upon CURLE_WRITE_ERROR */
      if(result)
        return result;
    }
    if(!per->prev || per->prev->config != config) {
      newfile = fopen(config->headerfile, "wb");
      if(newfile)
        fclose(newfile);
    }
    newfile = fopen(config->headerfile, "ab");

    if(!newfile) {
      errorf("Failed to open %s", config->headerfile);
      return CURLE_WRITE_ERROR;
    }
    else {
      heads->filename = config->headerfile;
      heads->s_isreg = TRUE;
      heads->fopened = TRUE;
      heads->stream = newfile;
    }
  }
  else {
    /* always use binary mode for protocol header output */
    CURLX_SET_BINMODE(heads->stream);
  }
  return CURLE_OK;
}

static CURLcode setup_outfile(struct OperationConfig *config,
                              struct per_transfer *per,
                              struct OutStruct *outs,
                              bool *skipped)
{
  /*
   * We have specified a filename to store the result in, or we have
   * decided we want to use the remote filename.
   */
  struct State *state = &global->state;

  if(!per->outfile) {
    /* extract the filename from the URL */
    CURLcode result = get_url_file_name(&per->outfile, per->url);
    if(result) {
      errorf("Failed to extract a filename"
             " from the URL to use for storage");
      return result;
    }
  }
  else if(glob_inuse(&state->urlglob)) {
    /* fill '#1' ... '#9' terms from URL pattern */
    char *storefile = per->outfile;
    CURLcode result =
      glob_match_url(&per->outfile, storefile, &state->urlglob);
    tool_safefree(storefile);
    if(result) {
      /* bad globbing */
      warnf("bad output glob");
      return result;
    }
    if(!*per->outfile) {
      warnf("output glob produces empty string");
      return CURLE_WRITE_ERROR;
    }
  }
  DEBUGASSERT(per->outfile);

  if(config->output_dir && *config->output_dir) {
    char *d = aprintf("%s/%s", config->output_dir, per->outfile);
    if(!d)
      return CURLE_WRITE_ERROR;
    free(per->outfile);
    per->outfile = d;
  }
  /* Create the directory hierarchy, if not pre-existent to a multiple
     file output call */

  if(config->create_dirs) {
    CURLcode result = create_dir_hierarchy(per->outfile);
    /* create_dir_hierarchy shows error upon CURLE_WRITE_ERROR */
    if(result)
      return result;
  }

  if(config->skip_existing) {
    struct_stat fileinfo;
    if(!stat(per->outfile, &fileinfo)) {
      /* file is present */
      notef("skips transfer, \"%s\" exists locally", per->outfile);
      per->skip = TRUE;
      *skipped = TRUE;
    }
  }

  if(config->resume_from_current) {
    /* We are told to continue from where we are now. Get the size
       of the file as it is now and open it for append instead */
    struct_stat fileinfo;
    /* VMS -- Danger, the filesize is only valid for stream files */
    if(stat(per->outfile, &fileinfo) == 0)
      /* set offset to current file size: */
      config->resume_from = fileinfo.st_size;
    else
      /* let offset be 0 */
      config->resume_from = 0;
  }

  if(config->resume_from) {
#ifdef __VMS
    /* open file for output, forcing VMS output format into stream
       mode which is needed for stat() call above to always work. */
    FILE *file = fopen(outfile, "ab",
                       "ctx=stm", "rfm=stmlf", "rat=cr", "mrs=0");
#else
    /* open file for output: */
    FILE *file = fopen(per->outfile, "ab");
#endif
    if(!file) {
      errorf("cannot open '%s'", per->outfile);
      return CURLE_WRITE_ERROR;
    }
    outs->fopened = TRUE;
    outs->stream = file;
    outs->init = config->resume_from;
  }
  else {
    outs->stream = NULL; /* open when needed */
  }
  outs->filename = per->outfile;
  outs->s_isreg = TRUE;
  return CURLE_OK;
}

static void check_stdin_upload(struct OperationConfig *config,
                               struct per_transfer *per)
{
  /* count to see if there are more than one auth bit set
     in the authtype field */
  int authbits = 0;
  int bitcheck = 0;
  while(bitcheck < 32) {
    if(config->authtype & (1UL << bitcheck++)) {
      authbits++;
      if(authbits > 1) {
        /* more than one, we are done! */
        break;
      }
    }
  }

  /*
   * If the user has also selected --anyauth or --proxy-anyauth
   * we should warn them.
   */
  if(config->proxyanyauth || (authbits > 1)) {
    warnf("Using --anyauth or --proxy-anyauth with upload from stdin"
          " involves a big risk of it not working. Use a temporary"
          " file or a fixed auth type instead");
  }

  DEBUGASSERT(per->infdopen == FALSE);
  DEBUGASSERT(per->infd == STDIN_FILENO);

  CURLX_SET_BINMODE(stdin);
  if(!strcmp(per->uploadfile, ".")) {
#if defined(_WIN32) && !defined(CURL_WINDOWS_UWP) && !defined(UNDER_CE)
    /* non-blocking stdin behavior on Windows is challenging
       Spawn a new thread that will read from stdin and write
       out to a socket */
    curl_socket_t f = win32_stdin_read_thread();

    if(f == CURL_SOCKET_BAD)
      warnf("win32_stdin_read_thread returned INVALID_SOCKET "
            "falling back to blocking mode");
    else if(f > INT_MAX) {
      warnf("win32_stdin_read_thread returned identifier "
            "larger than INT_MAX. This should not happen unless "
            "the upper 32 bits of a Windows socket have started "
            "being used for something... falling back to blocking "
            "mode");
      sclose(f);
    }
    else
      per->infd = (int)f;
#endif
    if(curlx_nonblock((curl_socket_t)per->infd, TRUE) < 0)
      warnf("fcntl failed on fd=%d: %s", per->infd, strerror(errno));
  }
}

/* create the next (singular) transfer */
static CURLcode single_transfer(struct OperationConfig *config,
                                CURLSH *share, bool *added, bool *skipped)
{
  CURLcode result = CURLE_OK;
  bool orig_noprogress = global->noprogress;
  bool orig_isatty = global->isatty;
  struct State *state = &global->state;
  char *httpgetfields = state->httpgetfields;

  *skipped = *added = FALSE; /* not yet */

  if(config->postfields) {
    if(config->use_httpget) {
      if(!httpgetfields) {
        /* Use the postfields data for an HTTP get */
        httpgetfields = state->httpgetfields = config->postfields;
        config->postfields = NULL;
        if(SetHTTPrequest((config->no_body ? TOOL_HTTPREQ_HEAD :
                           TOOL_HTTPREQ_GET), &config->httpreq))
          return CURLE_FAILED_INIT;
      }
    }
    else if(SetHTTPrequest(TOOL_HTTPREQ_SIMPLEPOST, &config->httpreq))
      return CURLE_FAILED_INIT;
  }

  result = set_cert_types(config);
  if(result)
    return result;

  if(!state->urlnode) {
    /* first time caller, setup things */
    state->urlnode = config->url_list;
    state->upnum = 1;
  }

  while(state->urlnode) {
    struct per_transfer *per = NULL;
    struct OutStruct *outs;
    struct OutStruct *heads;
    struct HdrCbData *hdrcbdata = NULL;
    struct OutStruct etag_first;
    CURL *curl;
    struct getout *u = state->urlnode;
    FILE *err = (!global->silent || global->showerror) ? tool_stderr : NULL;

    if(!u->url) {
      /* This node has no URL. End of the road. */
      warnf("Got more output options than URLs");
      break;
    }
    if(u->infile) {
      if(!config->globoff && !glob_inuse(&state->inglob))
        result = glob_url(&state->inglob, u->infile, &state->upnum, err);
      if(!state->uploadfile) {
        if(glob_inuse(&state->inglob))
          result = glob_next_url(&state->uploadfile, &state->inglob);
        else if(!state->upidx) {
          /* copy the allocated string */
          state->uploadfile = u->infile;
          u->infile = NULL;
        }
      }
      if(result)
        return result;
    }

    if(state->upidx >= state->upnum) {
      state->urlnum = 0;
      tool_safefree(state->uploadfile);
      glob_cleanup(&state->inglob);
      state->upidx = 0;
      state->urlnode = u->next; /* next node */
      continue;
    }

    if(!state->urlnum) {
      if(!config->globoff && !u->noglob) {
        /* Unless explicitly shut off, we expand '{...}' and '[...]'
           expressions and return total number of URLs in pattern set */
        result = glob_url(&state->urlglob, u->url, &state->urlnum, err);
        if(result)
          return result;
      }
      else
        state->urlnum = 1; /* without globbing, this is a single URL */
    }

    /* --etag-save */
    memset(&etag_first, 0, sizeof(etag_first));
    etag_first.stream = stdout;

    /* --etag-compare */
    if(config->etag_compare_file) {
      result = etag_compare(config);
      if(result)
        return result;
    }

    if(config->etag_save_file) {
      bool badetag = FALSE;
      result = etag_store(config, &etag_first, &badetag);
      if(result || badetag)
        break;
    }

    curl = curl_easy_init();
    if(curl)
      result = add_per_transfer(&per);
    else
      result = CURLE_OUT_OF_MEMORY;
    if(result) {
      curl_easy_cleanup(curl);
      if(etag_first.fopened)
        fclose(etag_first.stream);
      return result;
    }
    per->etag_save = etag_first; /* copy the whole struct */
    if(state->uploadfile) {
      per->uploadfile = strdup(state->uploadfile);
      if(!per->uploadfile ||
         SetHTTPrequest(TOOL_HTTPREQ_PUT, &config->httpreq)) {
        tool_safefree(per->uploadfile);
        curl_easy_cleanup(curl);
        return CURLE_FAILED_INIT;
      }
    }
    per->config = config;
    per->curl = curl;
    per->urlnum = u->num;

    /* default headers output stream is stdout */
    heads = &per->heads;
    heads->stream = stdout;

    /* Single header file for all URLs */
    if(config->headerfile) {
      result = setup_headerfile(config, per, heads);
      if(result)
        return result;
    }
    hdrcbdata = &per->hdrcbdata;

    outs = &per->outs;

    per->outfile = NULL;
    per->infdopen = FALSE;
    per->infd = STDIN_FILENO;

    /* default output stream is stdout */
    outs->stream = stdout;

    if(glob_inuse(&state->urlglob))
      result = glob_next_url(&per->url, &state->urlglob);
    else if(!state->urlidx) {
      per->url = strdup(u->url);
      if(!per->url)
        result = CURLE_OUT_OF_MEMORY;
    }
    else {
      per->url = NULL;
      break;
    }
    if(result)
      return result;

    if(u->outfile) {
      per->outfile = strdup(u->outfile);
      if(!per->outfile)
        return CURLE_OUT_OF_MEMORY;
    }

    outs->out_null = u->out_null;
    if(!outs->out_null &&
       (u->useremote || (per->outfile && strcmp("-", per->outfile)))) {
      result = setup_outfile(config, per, outs, skipped);
      if(result)
        return result;
    }

    if(per->uploadfile) {

      if(stdin_upload(per->uploadfile))
        check_stdin_upload(config, per);
      else {
        /*
         * We have specified a file to upload and it is not "-".
         */
        result = add_file_name_to_url(per->curl, &per->url,
                                      per->uploadfile);
        if(result)
          return result;
      }

      if(config->resume_from_current)
        config->resume_from = -1; /* -1 will then force get-it-yourself */
    }

    if(output_expected(per->url, per->uploadfile) && outs->stream &&
       isatty(fileno(outs->stream)))
      /* we send the output to a tty, therefore we switch off the progress
         meter */
      per->noprogress = global->noprogress = global->isatty = TRUE;
    else {
      /* progress meter is per download, so restore config
         values */
      per->noprogress = global->noprogress = orig_noprogress;
      global->isatty = orig_isatty;
    }

    if(httpgetfields || config->query) {
      result = append2query(config, per,
                            httpgetfields ? httpgetfields : config->query);
      if(result)
        return result;
    }

    if((!per->outfile || !strcmp(per->outfile, "-")) &&
       !config->use_ascii) {
      /* We get the output to stdout and we have not got the ASCII/text flag,
         then set stdout to be binary */
      CURLX_SET_BINMODE(stdout);
    }

    /* explicitly passed to stdout means okaying binary gunk */
    config->terminal_binary_ok =
      (per->outfile && !strcmp(per->outfile, "-"));

    hdrcbdata->honor_cd_filename =
      (config->content_disposition && u->useremote);
    hdrcbdata->outs = outs;
    hdrcbdata->heads = heads;
    hdrcbdata->etag_save = &etag_first;
    hdrcbdata->config = config;

    result = config2setopts(config, per, curl, share);
    if(result)
      return result;

    /* initialize retry vars for loop below */
    per->retry_sleep_default = config->retry_delay_ms;
    per->retry_remaining = config->req_retry;
    per->retry_sleep = per->retry_sleep_default; /* ms */
    per->retrystart = curlx_now();

    state->urlidx++;
    /* Here's looping around each globbed URL */
    if(state->urlidx >= state->urlnum) {
      state->urlidx = state->urlnum = 0;
      glob_cleanup(&state->urlglob);
      state->upidx++;
      tool_safefree(state->uploadfile); /* clear it to get the next */
    }
    *added = TRUE;
    break;
  }
  return result;
}

static long all_added; /* number of easy handles currently added */

/*
 * add_parallel_transfers() sets 'morep' to TRUE if there are more transfers
 * to add even after this call returns. sets 'addedp' to TRUE if one or more
 * transfers were added.
 */
static CURLcode add_parallel_transfers(CURLM *multi, CURLSH *share,
                                       bool *morep, bool *addedp)
{
  struct per_transfer *per;
  CURLcode result = CURLE_OK;
  CURLMcode mcode;
  bool sleeping = FALSE;
  curl_off_t nxfers;

  *addedp = FALSE;
  *morep = FALSE;
  mcode = curl_multi_get_offt(multi, CURLMINFO_XFERS_CURRENT, &nxfers);
  if(mcode) {
    DEBUGASSERT(0);
    return CURLE_UNKNOWN_OPTION;
  }

  if(nxfers < (curl_off_t)(global->parallel_max*2)) {
    bool skipped = FALSE;
    do {
      result = create_transfer(share, addedp, &skipped);
      if(result)
        return result;
    } while(skipped);
  }
  for(per = transfers; per && (all_added < global->parallel_max);
      per = per->next) {
    if(per->added || per->skip)
      /* already added or to be skipped */
      continue;
    if(per->startat && (time(NULL) < per->startat)) {
      /* this is still delaying */
      sleeping = TRUE;
      continue;
    }
    per->added = TRUE;

    result = pre_transfer(per);
    if(result)
      return result;

    /* parallel connect means that we do not set PIPEWAIT since pipewait
       will make libcurl prefer multiplexing */
    (void)curl_easy_setopt(per->curl, CURLOPT_PIPEWAIT,
                           global->parallel_connect ? 0L : 1L);
    (void)curl_easy_setopt(per->curl, CURLOPT_PRIVATE, per);
    /* curl does not use signals, switching this on saves some system calls */
    (void)curl_easy_setopt(per->curl, CURLOPT_NOSIGNAL, 1L);
    (void)curl_easy_setopt(per->curl, CURLOPT_XFERINFOFUNCTION, xferinfo_cb);
    (void)curl_easy_setopt(per->curl, CURLOPT_XFERINFODATA, per);
    (void)curl_easy_setopt(per->curl, CURLOPT_NOPROGRESS, 0L);
    (void)curl_easy_setopt(per->curl, CURLOPT_ERRORBUFFER, per->errorbuffer);
#ifdef DEBUGBUILD
    if(getenv("CURL_FORBID_REUSE"))
      (void)curl_easy_setopt(per->curl, CURLOPT_FORBID_REUSE, 1L);
#endif

    mcode = curl_multi_add_handle(multi, per->curl);
    if(mcode) {
      DEBUGASSERT(mcode == CURLM_OUT_OF_MEMORY);
      result = CURLE_OUT_OF_MEMORY;
    }

    if(!result) {
      bool getadded = FALSE;
      bool skipped = FALSE;
      do {
        result = create_transfer(share, &getadded, &skipped);
        if(result)
          break;
      } while(skipped);
    }
    if(result)
      return result;

    per->errorbuffer[0] = 0;
    per->added = TRUE;
    all_added++;
    *addedp = TRUE;
  }
  *morep = (per || sleeping);
  return CURLE_OK;
}

struct parastate {
  CURLM *multi;
  CURLSH *share;
  CURLMcode mcode;
  CURLcode result;
  int still_running;
  struct curltime start;
  bool more_transfers;
  bool added_transfers;
  /* wrapitup is set TRUE after a critical error occurs to end all transfers */
  bool wrapitup;
  /* wrapitup_processed is set TRUE after the per transfer abort flag is set */
  bool wrapitup_processed;
  time_t tick;
};

#if defined(DEBUGBUILD) && defined(USE_LIBUV)

#define DEBUG_UV    0

/* object to pass to the callbacks */
struct datauv {
  uv_timer_t timeout;
  uv_loop_t *loop;
  struct parastate *s;
};

struct contextuv {
  uv_poll_t poll_handle;
  curl_socket_t sockfd;
  struct datauv *uv;
};

static CURLcode check_finished(struct parastate *s);

static void check_multi_info(struct datauv *uv)
{
  CURLcode result;

  result = check_finished(uv->s);
  if(result && !uv->s->result)
    uv->s->result = result;

  if(uv->s->more_transfers) {
    result = add_parallel_transfers(uv->s->multi, uv->s->share,
                                    &uv->s->more_transfers,
                                    &uv->s->added_transfers);
    if(result && !uv->s->result)
      uv->s->result = result;
    if(result)
      uv_stop(uv->loop);
  }
}

/* callback from libuv on socket activity */
static void on_uv_socket(uv_poll_t *req, int status, int events)
{
  int flags = 0;
  struct contextuv *c = (struct contextuv *) req->data;
  (void)status;
  if(events & UV_READABLE)
    flags |= CURL_CSELECT_IN;
  if(events & UV_WRITABLE)
    flags |= CURL_CSELECT_OUT;

  curl_multi_socket_action(c->uv->s->multi, c->sockfd, flags,
                           &c->uv->s->still_running);
}

/* callback from libuv when timeout expires */
static void on_uv_timeout(uv_timer_t *req)
{
  struct datauv *uv = (struct datauv *) req->data;
#if DEBUG_UV
  fprintf(tool_stderr, "parallel_event: on_uv_timeout\n");
#endif
  if(uv && uv->s) {
    curl_multi_socket_action(uv->s->multi, CURL_SOCKET_TIMEOUT, 0,
                             &uv->s->still_running);
    check_multi_info(uv);
  }
}

/* callback from libcurl to update the timeout expiry */
static int cb_timeout(CURLM *multi, long timeout_ms, void *userp)
{
  struct datauv *uv = userp;
  (void)multi;
#if DEBUG_UV
  fprintf(tool_stderr, "parallel_event: cb_timeout=%ld\n", timeout_ms);
#endif
  if(timeout_ms < 0)
    uv_timer_stop(&uv->timeout);
  else {
    if(timeout_ms == 0)
      timeout_ms = 1; /* 0 means call curl_multi_socket_action asap but NOT
                         within the callback itself */
    uv_timer_start(&uv->timeout, on_uv_timeout, timeout_ms,
                   0); /* do not repeat */
  }
  return 0;
}

static struct contextuv *create_context(curl_socket_t sockfd,
                                        struct datauv *uv)
{
  struct contextuv *c;

  c = (struct contextuv *) malloc(sizeof(*c));

  c->sockfd = sockfd;
  c->uv = uv;

  uv_poll_init_socket(uv->loop, &c->poll_handle, sockfd);
  c->poll_handle.data = c;

  return c;
}

static void close_cb(uv_handle_t *handle)
{
  struct contextuv *c = (struct contextuv *) handle->data;
  free(c);
}

static void destroy_context(struct contextuv *c)
{
  uv_close((uv_handle_t *) &c->poll_handle, close_cb);
}

/* callback from libcurl to update socket activity to wait for */
static int cb_socket(CURL *easy, curl_socket_t s, int action,
                     void *userp, void *socketp)
{
  struct contextuv *c;
  int events = 0;
  struct datauv *uv = userp;
  (void)easy;

#if DEBUG_UV
  fprintf(tool_stderr, "parallel_event: cb_socket, fd=%d, action=%x, p=%p\n",
          (int)s, action, socketp);
#endif
  switch(action) {
  case CURL_POLL_IN:
  case CURL_POLL_OUT:
  case CURL_POLL_INOUT:
    c = socketp ?
      (struct contextuv *) socketp : create_context(s, uv);

    curl_multi_assign(uv->s->multi, s, c);

    if(action != CURL_POLL_IN)
      events |= UV_WRITABLE;
    if(action != CURL_POLL_OUT)
      events |= UV_READABLE;

    uv_poll_start(&c->poll_handle, events, on_uv_socket);
    break;
  case CURL_POLL_REMOVE:
    if(socketp) {
      c = (struct contextuv *)socketp;
      uv_poll_stop(&c->poll_handle);
      destroy_context(c);
      curl_multi_assign(uv->s->multi, s, NULL);
      /* check if we can do more now */
      check_multi_info(uv);
    }
    break;
  default:
    abort();
  }

  return 0;
}

static CURLcode parallel_event(struct parastate *s)
{
  CURLcode result = CURLE_OK;
  struct datauv uv = { 0 };

  s->result = CURLE_OK;
  uv.s = s;
  uv.loop = uv_default_loop();
  uv_timer_init(uv.loop, &uv.timeout);
  uv.timeout.data = &uv;

  /* setup event callbacks */
  curl_multi_setopt(s->multi, CURLMOPT_SOCKETFUNCTION, cb_socket);
  curl_multi_setopt(s->multi, CURLMOPT_SOCKETDATA, &uv);
  curl_multi_setopt(s->multi, CURLMOPT_TIMERFUNCTION, cb_timeout);
  curl_multi_setopt(s->multi, CURLMOPT_TIMERDATA, &uv);
  curl_multi_setopt(s->multi, CURLMOPT_MAX_HOST_CONNECTIONS, (long)
                    global->parallel_host);

  /* kickstart the thing */
  curl_multi_socket_action(s->multi, CURL_SOCKET_TIMEOUT, 0,
                           &s->still_running);

  while(!s->mcode && (s->still_running || s->more_transfers)) {
#if DEBUG_UV
    fprintf(tool_stderr, "parallel_event: uv_run(), mcode=%d, %d running, "
            "%d more\n", s->mcode, uv.s->still_running, s->more_transfers);
#endif
    uv_run(uv.loop, UV_RUN_DEFAULT);
#if DEBUG_UV
    fprintf(tool_stderr, "parallel_event: uv_run() returned\n");
#endif

    result = check_finished(s);
    if(result && !s->result)
      s->result = result;

    /* early exit called */
    if(s->wrapitup) {
      if(s->still_running && !s->wrapitup_processed) {
        struct per_transfer *per;
        for(per = transfers; per; per = per->next) {
          if(per->added)
            per->abort = TRUE;
        }
        s->wrapitup_processed = TRUE;
      }
      break;
    }

    if(s->more_transfers) {
      result = add_parallel_transfers(s->multi, s->share, &s->more_transfers,
                                      &s->added_transfers);
      if(result && !s->result)
        s->result = result;
    }
  }

  result = s->result;

  /* Make sure to return some kind of error if there was a multi problem */
  if(s->mcode) {
    result = (s->mcode == CURLM_OUT_OF_MEMORY) ? CURLE_OUT_OF_MEMORY :
      /* The other multi errors should never happen, so return
         something suitably generic */
      CURLE_BAD_FUNCTION_ARGUMENT;
  }

  /* We need to cleanup the multi here, since the uv context lives on the
   * stack and will be gone. multi_cleanup can triggere events! */
  curl_multi_cleanup(s->multi);

#if DEBUG_UV
  fprintf(tool_stderr, "DONE parallel_event -> %d, mcode=%d, %d running, "
          "%d more\n",
          result, s->mcode, uv.s->still_running, s->more_transfers);
#endif
  return result;
}

#endif

static CURLcode check_finished(struct parastate *s)
{
  CURLcode result = CURLE_OK;
  int rc;
  CURLMsg *msg;
  bool checkmore = FALSE;
  progress_meter(s->multi, &s->start, FALSE);
  do {
    msg = curl_multi_info_read(s->multi, &rc);
    if(msg) {
      bool retry;
      long delay;
      struct per_transfer *ended;
      CURL *easy = msg->easy_handle;
      CURLcode tres = msg->data.result;
      curl_easy_getinfo(easy, CURLINFO_PRIVATE, (void *)&ended);
      curl_multi_remove_handle(s->multi, easy);

      if(ended->abort && (tres == CURLE_ABORTED_BY_CALLBACK)) {
        msnprintf(ended->errorbuffer, CURL_ERROR_SIZE,
                  "Transfer aborted due to critical error "
                  "in another transfer");
      }
      tres = post_per_transfer(ended, tres, &retry, &delay);
      progress_finalize(ended); /* before it goes away */
      all_added--; /* one fewer added */
      checkmore = TRUE;
      if(retry) {
        ended->added = FALSE; /* add it again */
        /* we delay retries in full integer seconds only */
        ended->startat = delay ? time(NULL) + delay/1000 : 0;
      }
      else {
        /* result receives this transfer's error unless the transfer was
           marked for abort due to a critical error in another transfer */
        if(tres && (!ended->abort || !result))
          result = tres;
        if(is_fatal_error(result) || (result && global->fail_early))
          s->wrapitup = TRUE;
        (void)del_per_transfer(ended);
      }
    }
  } while(msg);
  if(!s->wrapitup) {
    if(!checkmore) {
      time_t tock = time(NULL);
      if(s->tick != tock) {
        checkmore = TRUE;
        s->tick = tock;
      }
    }
    if(checkmore) {
      /* one or more transfers completed, add more! */
      CURLcode tres = add_parallel_transfers(s->multi, s->share,
                                             &s->more_transfers,
                                             &s->added_transfers);
      if(tres)
        result = tres;
      if(s->added_transfers)
        /* we added new ones, make sure the loop does not exit yet */
        s->still_running = 1;
    }
    if(is_fatal_error(result) || (result && global->fail_early))
      s->wrapitup = TRUE;
  }
  return result;
}

static CURLcode parallel_transfers(CURLSH *share)
{
  CURLcode result;
  struct parastate p;
  struct parastate *s = &p;
  s->share = share;
  s->mcode = CURLM_OK;
  s->result = CURLE_OK;
  s->still_running = 1;
  s->start = curlx_now();
  s->wrapitup = FALSE;
  s->wrapitup_processed = FALSE;
  s->tick = time(NULL);
  s->multi = curl_multi_init();
  if(!s->multi)
    return CURLE_OUT_OF_MEMORY;

  result = add_parallel_transfers(s->multi, s->share,
                                  &s->more_transfers, &s->added_transfers);
  if(result) {
    curl_multi_cleanup(s->multi);
    return result;
  }

#ifdef DEBUGBUILD
  if(global->test_event_based)
#ifdef USE_LIBUV
    return parallel_event(s);
#else
    errorf("Testing --parallel event-based requires libuv");
#endif
  else
#endif

  if(all_added) {
    while(!s->mcode && (s->still_running || s->more_transfers)) {
      /* If stopping prematurely (eg due to a --fail-early condition) then
         signal that any transfers in the multi should abort (via progress
         callback). */
      if(s->wrapitup) {
        if(!s->still_running)
          break;
        if(!s->wrapitup_processed) {
          struct per_transfer *per;
          for(per = transfers; per; per = per->next) {
            if(per->added)
              per->abort = TRUE;
          }
          s->wrapitup_processed = TRUE;
        }
      }

      s->mcode = curl_multi_poll(s->multi, NULL, 0, 1000, NULL);
      if(!s->mcode)
        s->mcode = curl_multi_perform(s->multi, &s->still_running);
      if(!s->mcode)
        result = check_finished(s);
    }

    (void)progress_meter(s->multi, &s->start, TRUE);
  }

  /* Make sure to return some kind of error if there was a multi problem */
  if(s->mcode) {
    result = (s->mcode == CURLM_OUT_OF_MEMORY) ? CURLE_OUT_OF_MEMORY :
      /* The other multi errors should never happen, so return
         something suitably generic */
      CURLE_BAD_FUNCTION_ARGUMENT;
  }

  curl_multi_cleanup(s->multi);

  return result;
}

static CURLcode serial_transfers(CURLSH *share)
{
  CURLcode returncode = CURLE_OK;
  CURLcode result = CURLE_OK;
  struct per_transfer *per;
  bool added = FALSE;
  bool skipped = FALSE;

  result = create_transfer(share, &added, &skipped);
  if(result)
    return result;
  if(!added) {
    errorf("no transfer performed");
    return CURLE_READ_ERROR;
  }
  for(per = transfers; per;) {
    bool retry;
    long delay_ms;
    bool bailout = FALSE;
    struct curltime start;

    start = curlx_now();
    if(!per->skip) {
      result = pre_transfer(per);
      if(result)
        break;

      if(global->libcurl) {
        result = easysrc_perform();
        if(result)
          break;
      }

#ifdef DEBUGBUILD
      if(getenv("CURL_FORBID_REUSE"))
        (void)curl_easy_setopt(per->curl, CURLOPT_FORBID_REUSE, 1L);

      if(global->test_duphandle) {
        CURL *dup = curl_easy_duphandle(per->curl);
        curl_easy_cleanup(per->curl);
        per->curl = dup;
        if(!dup) {
          result = CURLE_OUT_OF_MEMORY;
          break;
        }
        /* a duplicate needs the share re-added */
        (void)curl_easy_setopt(per->curl, CURLOPT_SHARE, share);
      }
      if(global->test_event_based)
        result = curl_easy_perform_ev(per->curl);
      else
#endif
        result = curl_easy_perform(per->curl);
    }

    returncode = post_per_transfer(per, result, &retry, &delay_ms);
    if(retry) {
      curlx_wait_ms(delay_ms);
      continue;
    }

    /* Bail out upon critical errors or --fail-early */
    if(is_fatal_error(returncode) || (returncode && global->fail_early))
      bailout = TRUE;
    else {
      do {
        /* setup the next one just before we delete this */
        result = create_transfer(share, &added, &skipped);
        if(result) {
          returncode = result;
          bailout = TRUE;
          break;
        }
      } while(skipped);
    }

    per = del_per_transfer(per);

    if(bailout)
      break;

    if(per && global->ms_per_transfer) {
      /* how long time did the most recent transfer take in number of
         milliseconds */
      timediff_t milli = curlx_timediff(curlx_now(), start);
      if(milli < global->ms_per_transfer) {
        notef("Transfer took %" CURL_FORMAT_CURL_OFF_T " ms, "
              "waits %ldms as set by --rate",
              milli, (long)(global->ms_per_transfer - milli));
        /* The transfer took less time than wanted. Wait a little. */
        curlx_wait_ms((long)(global->ms_per_transfer - milli));
      }
    }
  }
  if(returncode)
    /* returncode errors have priority */
    result = returncode;

  if(result)
    single_transfer_cleanup();

  return result;
}

static CURLcode is_using_schannel(int *using)
{
  CURLcode result = CURLE_OK;
  static int using_schannel = -1; /* -1 = not checked
                                     0 = nope
                                     1 = yes */
  if(using_schannel == -1) {
    CURL *curltls = curl_easy_init();
    /* The TLS backend remains, so keep the info */
    struct curl_tlssessioninfo *tls_backend_info = NULL;

    if(!curltls)
      result = CURLE_OUT_OF_MEMORY;
    else {
      result = curl_easy_getinfo(curltls, CURLINFO_TLS_SSL_PTR,
                                 &tls_backend_info);
      if(!result)
        using_schannel =
          (tls_backend_info->backend == CURLSSLBACKEND_SCHANNEL);
    }
    curl_easy_cleanup(curltls);
    if(result)
      return result;
  }
  *using = using_schannel;
  return result;
}

/* Set the CA cert locations specified in the environment. For Windows if no
 * environment-specified filename is found then check for CA bundle default
 * filename curl-ca-bundle.crt in the user's PATH.
 *
 * If Schannel is the selected SSL backend then these locations are ignored.
 * We allow setting CA location for Schannel only when explicitly specified by
 * the user via CURLOPT_CAINFO / --cacert.
 */

static CURLcode cacertpaths(struct OperationConfig *config)
{
  CURLcode result = CURLE_OUT_OF_MEMORY;
  char *env = curl_getenv("CURL_CA_BUNDLE");
  if(env) {
    config->cacert = strdup(env);
    curl_free(env);
    if(!config->cacert)
      goto fail;
  }
  else {
    env = curl_getenv("SSL_CERT_DIR");
    if(env) {
      config->capath = strdup(env);
      curl_free(env);
      if(!config->capath)
        goto fail;
    }
    env = curl_getenv("SSL_CERT_FILE");
    if(env) {
      config->cacert = strdup(env);
      curl_free(env);
      if(!config->cacert)
        goto fail;
    }
  }

#ifdef _WIN32
  if(!env) {
#ifdef CURL_CA_SEARCH_SAFE
    char *cacert = NULL;
    FILE *cafile = tool_execpath("curl-ca-bundle.crt", &cacert);
    if(cafile) {
      fclose(cafile);
      config->cacert = strdup(cacert);
    }
#elif !defined(CURL_WINDOWS_UWP) && !defined(UNDER_CE) && \
  !defined(CURL_DISABLE_CA_SEARCH)
    result = FindWin32CACert(config, TEXT("curl-ca-bundle.crt"));
    if(result)
      goto fail;
#endif
  }
#endif
  return CURLE_OK;
fail:
  free(config->capath);
  return result;
}

/* setup a transfer for the given config */
static CURLcode transfer_per_config(struct OperationConfig *config,
                                    CURLSH *share,
                                    bool *added,
                                    bool *skipped)
{
  CURLcode result = CURLE_OK;
  *added = FALSE;

  /* Check we have a url */
  if(!config->url_list || !config->url_list->url) {
    helpf("(%d) no URL specified", CURLE_FAILED_INIT);
    return CURLE_FAILED_INIT;
  }

  /* On Windows we cannot set the path to curl-ca-bundle.crt at compile time.
   * We look for the file in two ways:
   * 1: look at the environment variable CURL_CA_BUNDLE for a path
   * 2: if #1 is not found, use the Windows API function SearchPath()
   *    to find it along the app's path (includes app's dir and CWD)
   *
   * We support the environment variable thing for non-Windows platforms
   * too. Just for the sake of it.
   */
  if(feature_ssl &&
     !config->cacert &&
     !config->capath &&
     (!config->insecure_ok || (config->doh_url && !config->doh_insecure_ok))) {
    int using_schannel = -1;

    result = is_using_schannel(&using_schannel);

    /* With the addition of CAINFO support for Schannel, this search could
     * find a certificate bundle that was previously ignored. To maintain
     * backward compatibility, only perform this search if not using Schannel.
     */
    if(!result && !using_schannel)
      result = cacertpaths(config);
  }

  if(!result) {
    result = single_transfer(config, share, added, skipped);
    if(!*added || result)
      single_transfer_cleanup();
  }

  return result;
}

/*
 * 'create_transfer' gets the details and sets up a new transfer if 'added'
 * returns TRUE.
 */
static CURLcode create_transfer(CURLSH *share,
                                bool *added,
                                bool *skipped)
{
  CURLcode result = CURLE_OK;
  *added = FALSE;
  while(global->current) {
    result = transfer_per_config(global->current, share, added, skipped);
    if(!result && !*added) {
      /* when one set is drained, continue to next */
      global->current = global->current->next;
      continue;
    }
    break;
  }
  return result;
}

static CURLcode run_all_transfers(CURLSH *share,
                                  CURLcode result)
{
  /* Save the values of noprogress and isatty to restore them later on */
  bool orig_noprogress = global->noprogress;
  bool orig_isatty = global->isatty;
  struct per_transfer *per;

  /* Time to actually do the transfers */
  if(!result) {
    if(global->parallel)
      result = parallel_transfers(share);
    else
      result = serial_transfers(share);
  }

  /* cleanup if there are any left */
  for(per = transfers; per;) {
    bool retry;
    long delay;
    CURLcode result2 = post_per_transfer(per, result, &retry, &delay);
    if(!result)
      /* do not overwrite the original error */
      result = result2;

    /* Free list of given URLs */
    clean_getout(per->config);

    per = del_per_transfer(per);
  }

  /* Reset the global config variables */
  global->noprogress = orig_noprogress;
  global->isatty = orig_isatty;


  return result;
}

CURLcode operate(int argc, argv_item_t argv[])
{
  CURLcode result = CURLE_OK;
  const char *first_arg;
#ifdef UNDER_CE
  first_arg = argc > 1 ? strdup(argv[1]) : NULL;
#else
  first_arg = argc > 1 ? convert_tchar_to_UTF8(argv[1]) : NULL;
#endif

#ifdef HAVE_SETLOCALE
  /* Override locale for number parsing (only) */
  setlocale(LC_ALL, "");
  setlocale(LC_NUMERIC, "C");
#endif

  /* Parse .curlrc if necessary */
  if((argc == 1) ||
     (first_arg && strncmp(first_arg, "-q", 2) &&
      strcmp(first_arg, "--disable"))) {
    parseconfig(NULL); /* ignore possible failure */

    /* If we had no arguments then make sure a url was specified in .curlrc */
    if((argc < 2) && (!global->first->url_list)) {
      helpf(NULL);
      result = CURLE_FAILED_INIT;
    }
  }

  unicodefree(first_arg);

  if(!result) {
    /* Parse the command line arguments */
    ParameterError res = parse_args(argc, argv);
    if(res) {
      result = CURLE_OK;

      /* Check if we were asked for the help */
      if(res == PARAM_HELP_REQUESTED)
        ; /* already done */
      /* Check if we were asked for the manual */
      else if(res == PARAM_MANUAL_REQUESTED) {
#ifdef USE_MANUAL
        hugehelp();
#else
        warnf("built-in manual was disabled at build-time");
#endif
      }
      /* Check if we were asked for the version information */
      else if(res == PARAM_VERSION_INFO_REQUESTED)
        tool_version_info();
      /* Check if we were asked to list the SSL engines */
      else if(res == PARAM_ENGINES_REQUESTED)
        tool_list_engines();
      /* Check if we were asked to dump the embedded CA bundle */
      else if(res == PARAM_CA_EMBED_REQUESTED) {
#ifdef CURL_CA_EMBED
        printf("%s", curl_ca_embed);
#endif
      }
      else if(res == PARAM_LIBCURL_UNSUPPORTED_PROTOCOL)
        result = CURLE_UNSUPPORTED_PROTOCOL;
      else if(res == PARAM_READ_ERROR)
        result = CURLE_READ_ERROR;
      else
        result = CURLE_FAILED_INIT;
    }
    else {
      if(global->libcurl) {
        /* Initialise the libcurl source output */
        result = easysrc_init();
      }

      /* Perform the main operations */
      if(!result) {
        size_t count = 0;
        struct OperationConfig *operation = global->first;
        CURLSH *share = curl_share_init();
        if(!share) {
          if(global->libcurl) {
            /* Cleanup the libcurl source output */
            easysrc_cleanup();
          }
          result = CURLE_OUT_OF_MEMORY;
        }

        if(!result) {
          curl_share_setopt(share, CURLSHOPT_SHARE, CURL_LOCK_DATA_COOKIE);
          curl_share_setopt(share, CURLSHOPT_SHARE, CURL_LOCK_DATA_DNS);
          curl_share_setopt(share, CURLSHOPT_SHARE,
                            CURL_LOCK_DATA_SSL_SESSION);
          /* Running parallel, use the multi connection cache */
          if(!global->parallel)
            curl_share_setopt(share, CURLSHOPT_SHARE, CURL_LOCK_DATA_CONNECT);
          curl_share_setopt(share, CURLSHOPT_SHARE, CURL_LOCK_DATA_PSL);
          curl_share_setopt(share, CURLSHOPT_SHARE, CURL_LOCK_DATA_HSTS);

          if(global->ssl_sessions && feature_ssls_export)
            result = tool_ssls_load(global->first, share,
                                    global->ssl_sessions);

          if(!result) {
            /* Get the required arguments for each operation */
            do {
              result = get_args(operation, count++);

              operation = operation->next;
            } while(!result && operation);

            /* Set the current operation pointer */
            global->current = global->first;

            /* now run! */
            result = run_all_transfers(share, result);

            if(global->ssl_sessions && feature_ssls_export) {
              CURLcode r2 = tool_ssls_save(global->first, share,
                                           global->ssl_sessions);
              if(r2 && !result)
                result = r2;
            }
          }

          curl_share_cleanup(share);
          if(global->libcurl) {
            /* Cleanup the libcurl source output */
            easysrc_cleanup();

            /* Dump the libcurl code if previously enabled */
            dumpeasysrc();
          }
        }
      }
      else
        errorf("out of memory");
    }
  }

  varcleanup();
  curl_free(global->knownhosts);

  return result;
}
