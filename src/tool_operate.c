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
/* Hack for Unity mode */
#ifdef HEADER_CURL_MEMDEBUG_H
#undef HEADER_CURL_MEMDEBUG_H
#undef freeaddrinfo
#undef getaddrinfo
#endif
/* this is for libuv-enabled debug builds only */
#include <uv.h>
#endif

#include "curlx.h"

#include "tool_binmode.h"
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
#include "tool_sleep.h"
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
#include "dynbuf.h"
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

#ifndef SOL_IP
#  define SOL_IP IPPROTO_IP
#endif

#define CURL_CA_CERT_ERRORMSG                                              \
  "More details here: https://curl.se/docs/sslcerts.html\n\n"              \
  "curl failed to verify the legitimacy of the server and therefore "      \
  "could not\nestablish a secure connection to it. To learn more about "   \
  "this situation and\nhow to fix it, please visit the webpage mentioned " \
  "above.\n"

static CURLcode single_transfer(struct GlobalConfig *global,
                                struct OperationConfig *config,
                                CURLSH *share,
                                bool capath_from_env,
                                bool *added,
                                bool *skipped);
static CURLcode create_transfer(struct GlobalConfig *global,
                                CURLSH *share,
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

#ifdef IP_TOS
static int get_address_family(curl_socket_t sockfd)
{
  struct sockaddr addr;
  curl_socklen_t addrlen = sizeof(addr);
  memset(&addr, 0, sizeof(addr));
  if(getsockname(sockfd, (struct sockaddr *)&addr, &addrlen) == 0)
    return addr.sa_family;
  return AF_UNSPEC;
}
#endif

#if defined(IP_TOS) || defined(IPV6_TCLASS) || defined(SO_PRIORITY)
static int sockopt_callback(void *clientp, curl_socket_t curlfd,
                            curlsocktype purpose)
{
  struct OperationConfig *config = (struct OperationConfig *)clientp;
  if(purpose != CURLSOCKTYPE_IPCXN)
    return CURL_SOCKOPT_OK;
  (void)config;
  (void)curlfd;
#if defined(IP_TOS) || defined(IPV6_TCLASS)
  if(config->ip_tos > 0) {
    int tos = (int)config->ip_tos;
    int result = 0;
    switch(get_address_family(curlfd)) {
    case AF_INET:
#ifdef IP_TOS
      result = setsockopt(curlfd, SOL_IP, IP_TOS, (void *)&tos, sizeof(tos));
#endif
      break;
#if defined(IPV6_TCLASS) && defined(AF_INET6)
    case AF_INET6:
      result = setsockopt(curlfd, IPPROTO_IPV6, IPV6_TCLASS,
                          (void *)&tos, sizeof(tos));
      break;
#endif
    }
    if(result < 0) {
      int error = errno;
      warnf(config->global,
            "Setting type of service to %d failed with errno %d: %s;\n",
            tos, error, strerror(error));
    }
  }
#endif
#ifdef SO_PRIORITY
  if(config->vlan_priority > 0) {
    int priority = (int)config->vlan_priority;
    if(setsockopt(curlfd, SOL_SOCKET, SO_PRIORITY,
      (void *)&priority, sizeof(priority)) != 0) {
      int error = errno;
      warnf(config->global, "VLAN priority %d failed with errno %d: %s;\n",
            priority, error, strerror(error));
    }
  }
#endif
  return CURL_SOCKOPT_OK;
}
#endif


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

#define BUFFER_SIZE (100*1024)

struct per_transfer *transfers; /* first node */
static struct per_transfer *transfersl; /* last node */
static curl_off_t all_pers;

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
  all_xfers++; /* count total number of transfers added */
  all_pers++;

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
  all_pers--;

  return n;
}

static CURLcode pre_transfer(struct GlobalConfig *global,
                             struct per_transfer *per)
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
      helpf(tool_stderr, "cannot open '%s'", per->uploadfile);
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

    if(uploadfilesize != -1) {
      struct OperationConfig *config = per->config; /* for the macro below */
#ifdef CURL_DISABLE_LIBCURL_OPTION
      (void)config;
      (void)global;
#endif
      my_setopt(per->curl, CURLOPT_INFILESIZE_LARGE, uploadfilesize);
    }
  }
  per->uploadfilesize = uploadfilesize;
  per->start = tvnow();
  return result;
}

/* When doing serial transfers, we use a single fixed error area */
static char global_errorbuffer[CURL_ERROR_SIZE];

void single_transfer_cleanup(struct OperationConfig *config)
{
  if(config) {
    struct State *state = &config->state;
    /* Free list of remaining URLs */
    glob_cleanup(&state->urls);
    Curl_safefree(state->outfiles);
    Curl_safefree(state->uploadfile);
    /* Free list of globbed upload files */
    glob_cleanup(&state->inglob);
  }
}

/*
 * Call this after a transfer has completed.
 */
static CURLcode post_per_transfer(struct GlobalConfig *global,
                                  struct per_transfer *per,
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

  if(per->infdopen)
    close(per->infd);

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
              (msg && msg[0]) ? msg : curl_easy_strerror(result));
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
      warnf(config->global, "Error setting extended attributes on '%s': %s",
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
      errorf(global, "Failed writing body");
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
     (!config->retry_maxtime ||
      (tvdiff(tvnow(), per->retrystart) <
       config->retry_maxtime*1000L)) ) {
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
      if(ECONNREFUSED == oserrno)
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
           * TODO: similar action for the upload case. We might need
           * to start over reading from a previous point if we have
           * uploaded something when this was returned.
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
          if(config->retry_maxtime) {
            curl_off_t seconds = tvdiff(tvnow(), per->retrystart)/1000;

            if((CURL_OFF_T_MAX - retry_after < seconds) ||
               (seconds + retry_after > config->retry_maxtime)) {
              warnf(config->global, "The Retry-After: time would "
                    "make this command line exceed the maximum allowed time "
                    "for retries.");
              goto noretry;
            }
          }
        }
      }
      warnf(config->global, "Problem %s. "
            "Will retry in %ld seconds. "
            "%ld retries left.",
            m[retry], sleeptime/1000L, per->retry_remaining);

      per->retry_remaining--;
      if(!config->retry_delay) {
        per->retry_sleep *= 2;
        if(per->retry_sleep > RETRY_SLEEP_MAX)
          per->retry_sleep = RETRY_SLEEP_MAX;
      }
      if(outs->bytes && outs->filename && outs->stream) {
        /* We have written data to an output file, we truncate file
         */
        notef(config->global,
              "Throwing away %"  CURL_FORMAT_CURL_OFF_T " bytes",
              outs->bytes);
        fflush(outs->stream);
        /* truncate file at the position where we started appending */
#if defined(HAVE_FTRUNCATE) && !defined(__DJGPP__) && !defined(__AMIGA__)
        if(ftruncate(fileno(outs->stream), outs->init)) {
          /* when truncate fails, we cannot just append as then we will
             create something strange, bail out */
          errorf(config->global, "Failed to truncate file");
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
          errorf(config->global, "Failed seeking to end of file");
          return CURLE_WRITE_ERROR;
        }
        outs->bytes = 0; /* clear for next round */
      }
      *retryp = TRUE;
      per->num_retries++;
      *delay = sleeptime;
      return CURLE_OK;
    }
  } /* if retry_remaining */
noretry:

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
      errorf(config->global, "curl: (%d) Failed writing body", result);
    }
    if(result && config->rm_partial) {
      struct_stat st;
      if(!stat(outs->filename, &st) &&
         S_ISREG(st.st_mode)) {
        if(!unlink(outs->filename))
          notef(global, "Removed output file: %s", outs->filename);
        else
          warnf(global, "Failed removing: %s", outs->filename);
      }
      else
        warnf(global, "Skipping removal; not a regular file: %s",
              outs->filename);
    }
  }

  /* File time can only be set _after_ the file has been closed */
  if(!result && config->remote_time && outs->s_isreg && outs->filename) {
    /* Ask libcurl if we got a remote file time */
    curl_off_t filetime = -1;
    curl_easy_getinfo(curl, CURLINFO_FILETIME_T, &filetime);
    setfiletime(filetime, outs->filename, global);
  }
skip:
  /* Write the --write-out data before cleanup but after result is final */
  if(config->writeout)
    ourWriteOut(config, per, result);

  /* Close function-local opened file descriptors */
  if(per->heads.fopened && per->heads.stream)
    fclose(per->heads.stream);

  if(per->heads.alloc_filename)
    Curl_safefree(per->heads.filename);

  if(per->etag_save.fopened && per->etag_save.stream)
    fclose(per->etag_save.stream);

  if(per->etag_save.alloc_filename)
    Curl_safefree(per->etag_save.filename);

  curl_easy_cleanup(per->curl);
  if(outs->alloc_filename)
    free(outs->filename);
  free(per->url);
  free(per->outfile);
  free(per->uploadfile);
  if(global->parallel)
    free(per->errorbuffer);
  curl_slist_free_all(per->hdrcbdata.headlist);
  per->hdrcbdata.headlist = NULL;
  return result;
}

/*
 * Possibly rewrite the URL for IPFS and return the protocol token for the
 * scheme used in the given URL.
 */
static CURLcode url_proto_and_rewrite(char **url,
                                      struct OperationConfig *config,
                                      const char **scheme)
{
  CURLcode result = CURLE_OK;
  CURLU *uh = curl_url();
  const char *proto = NULL;
  *scheme = NULL;

  DEBUGASSERT(url && *url);
  if(uh) {
    char *schemep = NULL;
    if(!curl_url_set(uh, CURLUPART_URL, *url,
                     CURLU_GUESS_SCHEME | CURLU_NON_SUPPORT_SCHEME) &&
       !curl_url_get(uh, CURLUPART_SCHEME, &schemep,
                     CURLU_DEFAULT_SCHEME)) {
#ifdef CURL_DISABLE_IPFS
      (void)config;
#else
      if(curl_strequal(schemep, proto_ipfs) ||
         curl_strequal(schemep, proto_ipns)) {
        result = ipfs_url_rewrite(uh, schemep, url, config);
        /* short-circuit proto_token, we know it is ipfs or ipns */
        if(curl_strequal(schemep, proto_ipfs))
          proto = proto_ipfs;
        else if(curl_strequal(schemep, proto_ipns))
          proto = proto_ipns;
        if(result)
          config->synthetic_error = TRUE;
      }
      else
#endif /* !CURL_DISABLE_IPFS */
        proto = proto_token(schemep);

      curl_free(schemep);
    }
    curl_url_cleanup(uh);
  }
  else
    result = CURLE_OUT_OF_MEMORY;

  *scheme = proto ? proto : "?"; /* Never match if not found. */
  return result;
}

/* return current SSL backend name, chop off multissl */
static char *ssl_backend(void)
{
  static char ssl_ver[80] = "no ssl";
  static bool already = FALSE;
  if(!already) { /* if there is no existing version */
    const char *v = curl_version_info(CURLVERSION_NOW)->ssl_version;
    if(v)
      msnprintf(ssl_ver, sizeof(ssl_ver), "%.*s", (int) strcspn(v, " "), v);
    already = TRUE;
  }
  return ssl_ver;
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

static CURLcode config2setopts(struct GlobalConfig *global,
                               struct OperationConfig *config,
                               struct per_transfer *per,
                               bool capath_from_env,
                               CURL *curl,
                               CURLSH *share)
{
  const char *use_proto;
  CURLcode result = url_proto_and_rewrite(&per->url, config, &use_proto);

  /* Avoid having this setopt added to the --libcurl source output. */
  if(!result)
    result = curl_easy_setopt(curl, CURLOPT_SHARE, share);
  if(result)
    return result;

#ifndef DEBUGBUILD
  /* On most modern OSes, exiting works thoroughly,
     we will clean everything up via exit(), so do not bother with
     slow cleanups. Crappy ones might need to skip this.
     Note: avoid having this setopt added to the --libcurl source
     output. */
  result = curl_easy_setopt(curl, CURLOPT_QUICK_EXIT, 1L);
  if(result)
    return result;
#endif

  if(!config->tcp_nodelay)
    my_setopt(curl, CURLOPT_TCP_NODELAY, 0L);

  if(config->tcp_fastopen)
    my_setopt(curl, CURLOPT_TCP_FASTOPEN, 1L);

  if(config->mptcp)
    my_setopt(curl, CURLOPT_OPENSOCKETFUNCTION,
              tool_socket_open_mptcp_cb);

  /* where to store */
  my_setopt(curl, CURLOPT_WRITEDATA, per);
  my_setopt(curl, CURLOPT_INTERLEAVEDATA, per);

  /* what call to write */
  my_setopt(curl, CURLOPT_WRITEFUNCTION, tool_write_cb);

  /* Note that if CURLOPT_READFUNCTION is fread (the default), then
   * lib/telnet.c will Curl_poll() on the input file descriptor
   * rather than calling the READFUNCTION at regular intervals.
   * The circumstances in which it is preferable to enable this
   * behavior, by omitting to set the READFUNCTION & READDATA options,
   * have not been determined.
   */
  my_setopt(curl, CURLOPT_READDATA, per);
  /* what call to read */
  my_setopt(curl, CURLOPT_READFUNCTION, tool_read_cb);

  /* in 7.18.0, the CURLOPT_SEEKFUNCTION/DATA pair is taking over what
     CURLOPT_IOCTLFUNCTION/DATA pair previously provided for seeking */
  my_setopt(curl, CURLOPT_SEEKDATA, per);
  my_setopt(curl, CURLOPT_SEEKFUNCTION, tool_seek_cb);

  {
#ifdef DEBUGBUILD
    char *env = getenv("CURL_BUFFERSIZE");
    if(env) {
      long size = strtol(env, NULL, 10);
      if(size)
        my_setopt(curl, CURLOPT_BUFFERSIZE, size);
    }
    else
#endif
      if(config->recvpersecond &&
         (config->recvpersecond < BUFFER_SIZE))
        /* use a smaller sized buffer for better sleeps */
        my_setopt(curl, CURLOPT_BUFFERSIZE, (long)config->recvpersecond);
      else
        my_setopt(curl, CURLOPT_BUFFERSIZE, (long)BUFFER_SIZE);
  }

  my_setopt_str(curl, CURLOPT_URL, per->url);
  my_setopt(curl, CURLOPT_NOPROGRESS,
            global->noprogress || global->silent ? 1L : 0L);
  if(config->no_body)
    my_setopt(curl, CURLOPT_NOBODY, 1L);

  if(config->oauth_bearer)
    my_setopt_str(curl, CURLOPT_XOAUTH2_BEARER, config->oauth_bearer);

  my_setopt_str(curl, CURLOPT_PROXY, config->proxy);

  if(config->proxy && result) {
    errorf(global, "proxy support is disabled in this libcurl");
    config->synthetic_error = TRUE;
    return CURLE_NOT_BUILT_IN;
  }

  /* new in libcurl 7.5 */
  if(config->proxy)
    my_setopt_enum(curl, CURLOPT_PROXYTYPE, config->proxyver);

  my_setopt_str(curl, CURLOPT_PROXYUSERPWD, config->proxyuserpwd);

  /* new in libcurl 7.3 */
  my_setopt(curl, CURLOPT_HTTPPROXYTUNNEL, config->proxytunnel ?
            1L : 0L);

  /* new in libcurl 7.52.0 */
  if(config->preproxy)
    my_setopt_str(curl, CURLOPT_PRE_PROXY, config->preproxy);

  /* new in libcurl 7.10.6 */
  if(config->proxyanyauth)
    my_setopt_bitmask(curl, CURLOPT_PROXYAUTH, (long)CURLAUTH_ANY);
  else if(config->proxynegotiate)
    my_setopt_bitmask(curl, CURLOPT_PROXYAUTH, CURLAUTH_GSSNEGOTIATE);
  else if(config->proxyntlm)
    my_setopt_bitmask(curl, CURLOPT_PROXYAUTH, CURLAUTH_NTLM);
  else if(config->proxydigest)
    my_setopt_bitmask(curl, CURLOPT_PROXYAUTH, CURLAUTH_DIGEST);
  else if(config->proxybasic)
    my_setopt_bitmask(curl, CURLOPT_PROXYAUTH, CURLAUTH_BASIC);

  /* new in libcurl 7.19.4 */
  my_setopt_str(curl, CURLOPT_NOPROXY, config->noproxy);

  my_setopt(curl, CURLOPT_SUPPRESS_CONNECT_HEADERS,
            config->suppress_connect_headers ? 1L : 0L);

  my_setopt(curl, CURLOPT_FAILONERROR, config->failonerror ? 1L : 0L);
  my_setopt(curl, CURLOPT_REQUEST_TARGET, config->request_target);
  my_setopt(curl, CURLOPT_UPLOAD, per->uploadfile ? 1L : 0L);
  my_setopt(curl, CURLOPT_DIRLISTONLY, config->dirlistonly ? 1L : 0L);
  my_setopt(curl, CURLOPT_APPEND, config->ftp_append ? 1L : 0L);

  if(config->netrc_opt)
    my_setopt_enum(curl, CURLOPT_NETRC, (long)CURL_NETRC_OPTIONAL);
  else if(config->netrc || config->netrc_file)
    my_setopt_enum(curl, CURLOPT_NETRC, (long)CURL_NETRC_REQUIRED);
  else
    my_setopt_enum(curl, CURLOPT_NETRC, (long)CURL_NETRC_IGNORED);

  if(config->netrc_file)
    my_setopt_str(curl, CURLOPT_NETRC_FILE, config->netrc_file);

  my_setopt(curl, CURLOPT_TRANSFERTEXT, config->use_ascii ? 1L : 0L);
  if(config->login_options)
    my_setopt_str(curl, CURLOPT_LOGIN_OPTIONS, config->login_options);
  my_setopt_str(curl, CURLOPT_USERPWD, config->userpwd);
  my_setopt_str(curl, CURLOPT_RANGE, config->range);
  if(!global->parallel) {
    per->errorbuffer = global_errorbuffer;
    my_setopt(curl, CURLOPT_ERRORBUFFER, global_errorbuffer);
  }
  my_setopt(curl, CURLOPT_TIMEOUT_MS, config->timeout_ms);

  switch(config->httpreq) {
  case TOOL_HTTPREQ_SIMPLEPOST:
    if(config->resume_from) {
      errorf(global, "cannot mix --continue-at with --data");
      result = CURLE_FAILED_INIT;
    }
    else {
      my_setopt_str(curl, CURLOPT_POSTFIELDS,
                    curlx_dyn_ptr(&config->postdata));
      my_setopt(curl, CURLOPT_POSTFIELDSIZE_LARGE,
                (curl_off_t)curlx_dyn_len(&config->postdata));
    }
    break;
  case TOOL_HTTPREQ_MIMEPOST:
    /* free previous remainders */
    curl_mime_free(config->mimepost);
    config->mimepost = NULL;
    if(config->resume_from) {
      errorf(global, "cannot mix --continue-at with --form");
      result = CURLE_FAILED_INIT;
    }
    else {
      result = tool2curlmime(curl, config->mimeroot, &config->mimepost);
      if(!result)
        my_setopt_mimepost(curl, CURLOPT_MIMEPOST, config->mimepost);
    }
    break;
  default:
    break;
  }
  if(result)
    return result;

  /* new in libcurl 7.81.0 */
  if(config->mime_options)
    my_setopt(curl, CURLOPT_MIME_OPTIONS, config->mime_options);

  /* new in libcurl 7.10.6 (default is Basic) */
  if(config->authtype)
    my_setopt_bitmask(curl, CURLOPT_HTTPAUTH, (long)config->authtype);

  my_setopt_slist(curl, CURLOPT_HTTPHEADER, config->headers);

  if(proto_http || proto_rtsp) {
    my_setopt_str(curl, CURLOPT_REFERER, config->referer);
    my_setopt_str(curl, CURLOPT_USERAGENT, config->useragent);
  }

  if(proto_http) {
    long postRedir = 0;

    my_setopt(curl, CURLOPT_FOLLOWLOCATION,
              config->followlocation ? 1L : 0L);
    my_setopt(curl, CURLOPT_UNRESTRICTED_AUTH,
              config->unrestricted_auth ? 1L : 0L);
    my_setopt_str(curl, CURLOPT_AWS_SIGV4, config->aws_sigv4);
    my_setopt(curl, CURLOPT_AUTOREFERER, config->autoreferer ? 1L : 0L);

    /* new in libcurl 7.36.0 */
    if(config->proxyheaders) {
      my_setopt_slist(curl, CURLOPT_PROXYHEADER, config->proxyheaders);
      my_setopt(curl, CURLOPT_HEADEROPT, (long)CURLHEADER_SEPARATE);
    }

    /* new in libcurl 7.5 */
    my_setopt(curl, CURLOPT_MAXREDIRS, config->maxredirs);

    if(config->httpversion)
      my_setopt_enum(curl, CURLOPT_HTTP_VERSION, config->httpversion);
    else if(feature_http2)
      my_setopt_enum(curl, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_2TLS);

    /* curl 7.19.1 (the 301 version existed in 7.18.2),
       303 was added in 7.26.0 */
    if(config->post301)
      postRedir |= CURL_REDIR_POST_301;
    if(config->post302)
      postRedir |= CURL_REDIR_POST_302;
    if(config->post303)
      postRedir |= CURL_REDIR_POST_303;
    my_setopt(curl, CURLOPT_POSTREDIR, postRedir);

    /* new in libcurl 7.21.6 */
    if(config->encoding)
      my_setopt_str(curl, CURLOPT_ACCEPT_ENCODING, "");

    /* new in libcurl 7.21.6 */
    if(config->tr_encoding)
      my_setopt(curl, CURLOPT_TRANSFER_ENCODING, 1L);
    /* new in libcurl 7.64.0 */
    my_setopt(curl, CURLOPT_HTTP09_ALLOWED,
              config->http09_allowed ? 1L : 0L);
    if(result) {
      errorf(global, "HTTP/0.9 is not supported in this build");
      return result;
    }

  } /* (proto_http) */

  if(proto_ftp)
    my_setopt_str(curl, CURLOPT_FTPPORT, config->ftpport);
  my_setopt(curl, CURLOPT_LOW_SPEED_LIMIT,
            config->low_speed_limit);
  my_setopt(curl, CURLOPT_LOW_SPEED_TIME, config->low_speed_time);
  my_setopt(curl, CURLOPT_MAX_SEND_SPEED_LARGE,
            config->sendpersecond);
  my_setopt(curl, CURLOPT_MAX_RECV_SPEED_LARGE,
            config->recvpersecond);

  if(config->use_resume)
    my_setopt(curl, CURLOPT_RESUME_FROM_LARGE, config->resume_from);
  else
    my_setopt(curl, CURLOPT_RESUME_FROM_LARGE, CURL_OFF_T_C(0));

  my_setopt_str(curl, CURLOPT_KEYPASSWD, config->key_passwd);
  my_setopt_str(curl, CURLOPT_PROXY_KEYPASSWD, config->proxy_key_passwd);

  if(use_proto == proto_scp || use_proto == proto_sftp) {
    /* SSH and SSL private key uses same command-line option */
    /* new in libcurl 7.16.1 */
    my_setopt_str(curl, CURLOPT_SSH_PRIVATE_KEYFILE, config->key);
    /* new in libcurl 7.16.1 */
    my_setopt_str(curl, CURLOPT_SSH_PUBLIC_KEYFILE, config->pubkey);

    /* new in libcurl 7.17.1: SSH host key md5 checking allows us
       to fail if we are not talking to who we think we should */
    my_setopt_str(curl, CURLOPT_SSH_HOST_PUBLIC_KEY_MD5,
                  config->hostpubmd5);

    /* new in libcurl 7.80.0: SSH host key sha256 checking allows us
       to fail if we are not talking to who we think we should */
    my_setopt_str(curl, CURLOPT_SSH_HOST_PUBLIC_KEY_SHA256,
                  config->hostpubsha256);

    /* new in libcurl 7.56.0 */
    if(config->ssh_compression)
      my_setopt(curl, CURLOPT_SSH_COMPRESSION, 1L);

    if(!config->insecure_ok) {
      char *known = findfile(".ssh/known_hosts", FALSE);
      if(known) {
        /* new in curl 7.19.6 */
        result = res_setopt_str(curl, CURLOPT_SSH_KNOWNHOSTS, known);
        curl_free(known);
        if(result == CURLE_UNKNOWN_OPTION)
          /* libssh2 version older than 1.1.1 */
          result = CURLE_OK;
        if(result)
          return result;
      }
      else
        warnf(global, "Couldn't find a known_hosts file");
    }
  }

  if(config->cacert)
    my_setopt_str(curl, CURLOPT_CAINFO, config->cacert);
  if(config->proxy_cacert)
    my_setopt_str(curl, CURLOPT_PROXY_CAINFO, config->proxy_cacert);

  if(config->capath) {
    result = res_setopt_str(curl, CURLOPT_CAPATH, config->capath);
    if(result == CURLE_NOT_BUILT_IN) {
      warnf(global, "ignoring %s, not supported by libcurl with %s",
            capath_from_env ?
            "SSL_CERT_DIR environment variable" : "--capath",
            ssl_backend());
    }
    else if(result)
      return result;
  }
  /* For the time being if --proxy-capath is not set then we use the
     --capath value for it, if any. See #1257 */
  if(config->proxy_capath || config->capath) {
    result = res_setopt_str(curl, CURLOPT_PROXY_CAPATH,
                            (config->proxy_capath ?
                             config->proxy_capath :
                             config->capath));
    if((result == CURLE_NOT_BUILT_IN) ||
       (result == CURLE_UNKNOWN_OPTION)) {
      if(config->proxy_capath) {
        warnf(global, "ignoring %s, not supported by libcurl with %s",
              config->proxy_capath ? "--proxy-capath" : "--capath",
              ssl_backend());
      }
    }
    else if(result)
      return result;
  }

#ifdef CURL_CA_EMBED
  if(!config->cacert && !config->capath) {
    struct curl_blob blob;
    blob.data = (void *)curl_ca_embed;
    blob.len = strlen((const char *)curl_ca_embed);
    blob.flags = CURL_BLOB_NOCOPY;
    notef(config->global,
          "Using embedded CA bundle (%zu bytes)",
          blob.len);
    result = curl_easy_setopt(curl, CURLOPT_CAINFO_BLOB, &blob);
    if(result == CURLE_NOT_BUILT_IN) {
      warnf(global, "ignoring %s, not supported by libcurl with %s",
            "embedded CA bundle", ssl_backend());
    }
  }
  if(!config->proxy_cacert && !config->proxy_capath) {
    struct curl_blob blob;
    blob.data = (void *)curl_ca_embed;
    blob.len = strlen((const char *)curl_ca_embed);
    blob.flags = CURL_BLOB_NOCOPY;
    notef(config->global,
          "Using embedded CA bundle, for proxies (%zu bytes)",
          blob.len);
    result = curl_easy_setopt(curl, CURLOPT_PROXY_CAINFO_BLOB, &blob);
    if(result == CURLE_NOT_BUILT_IN) {
      warnf(global, "ignoring %s, not supported by libcurl with %s",
            "embedded CA bundle", ssl_backend());
    }
  }
#endif

  if(config->crlfile)
    my_setopt_str(curl, CURLOPT_CRLFILE, config->crlfile);
  if(config->proxy_crlfile)
    my_setopt_str(curl, CURLOPT_PROXY_CRLFILE, config->proxy_crlfile);
  else if(config->crlfile) /* CURLOPT_PROXY_CRLFILE default is crlfile */
    my_setopt_str(curl, CURLOPT_PROXY_CRLFILE, config->crlfile);

  if(config->pinnedpubkey) {
    result = res_setopt_str(curl, CURLOPT_PINNEDPUBLICKEY,
                            config->pinnedpubkey);
    if(result == CURLE_NOT_BUILT_IN)
      warnf(global, "ignoring %s, not supported by libcurl with %s",
            "--pinnedpubkey", ssl_backend());
  }
  if(config->proxy_pinnedpubkey) {
    result = res_setopt_str(curl, CURLOPT_PROXY_PINNEDPUBLICKEY,
                            config->proxy_pinnedpubkey);
    if(result == CURLE_NOT_BUILT_IN)
      warnf(global, "ignoring %s, not supported by libcurl with %s",
            "--proxy-pinnedpubkey", ssl_backend());
  }

  if(config->ssl_ec_curves)
    my_setopt_str(curl, CURLOPT_SSL_EC_CURVES, config->ssl_ec_curves);

  if(config->writeout)
    my_setopt_str(curl, CURLOPT_CERTINFO, 1L);

  if(feature_ssl) {
    my_setopt_str(curl, CURLOPT_SSLCERT, config->cert);
    my_setopt_str(curl, CURLOPT_PROXY_SSLCERT, config->proxy_cert);
    my_setopt_str(curl, CURLOPT_SSLCERTTYPE, config->cert_type);
    my_setopt_str(curl, CURLOPT_PROXY_SSLCERTTYPE,
                  config->proxy_cert_type);
    my_setopt_str(curl, CURLOPT_SSLKEY, config->key);
    my_setopt_str(curl, CURLOPT_PROXY_SSLKEY, config->proxy_key);
    my_setopt_str(curl, CURLOPT_SSLKEYTYPE, config->key_type);
    my_setopt_str(curl, CURLOPT_PROXY_SSLKEYTYPE,
                  config->proxy_key_type);

    /* libcurl default is strict verifyhost -> 1L, verifypeer -> 1L */
    if(config->insecure_ok) {
      my_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
      my_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
    }

    if(config->doh_insecure_ok) {
      my_setopt(curl, CURLOPT_DOH_SSL_VERIFYPEER, 0L);
      my_setopt(curl, CURLOPT_DOH_SSL_VERIFYHOST, 0L);
    }

    if(config->proxy_insecure_ok) {
      my_setopt(curl, CURLOPT_PROXY_SSL_VERIFYPEER, 0L);
      my_setopt(curl, CURLOPT_PROXY_SSL_VERIFYHOST, 0L);
    }

    if(config->verifystatus)
      my_setopt(curl, CURLOPT_SSL_VERIFYSTATUS, 1L);

    if(config->doh_verifystatus)
      my_setopt(curl, CURLOPT_DOH_SSL_VERIFYSTATUS, 1L);

    if(config->falsestart)
      my_setopt(curl, CURLOPT_SSL_FALSESTART, 1L);

    my_setopt_SSLVERSION(curl, CURLOPT_SSLVERSION,
                         config->ssl_version | config->ssl_version_max);
    if(config->proxy)
      my_setopt_SSLVERSION(curl, CURLOPT_PROXY_SSLVERSION,
                           config->proxy_ssl_version);

    {
      long mask =
        (config->ssl_allow_beast ?
         CURLSSLOPT_ALLOW_BEAST : 0) |
        (config->ssl_allow_earlydata ?
         CURLSSLOPT_EARLYDATA : 0) |
        (config->ssl_no_revoke ?
         CURLSSLOPT_NO_REVOKE : 0) |
        (config->ssl_revoke_best_effort ?
         CURLSSLOPT_REVOKE_BEST_EFFORT : 0) |
        (config->native_ca_store ?
         CURLSSLOPT_NATIVE_CA : 0) |
        (config->ssl_auto_client_cert ?
         CURLSSLOPT_AUTO_CLIENT_CERT : 0);

      if(mask)
        my_setopt_bitmask(curl, CURLOPT_SSL_OPTIONS, mask);
    }

    {
      long mask =
        (config->proxy_ssl_allow_beast ?
         CURLSSLOPT_ALLOW_BEAST : 0) |
        (config->proxy_ssl_auto_client_cert ?
         CURLSSLOPT_AUTO_CLIENT_CERT : 0) |
        (config->proxy_native_ca_store ?
         CURLSSLOPT_NATIVE_CA : 0);

      if(mask)
        my_setopt_bitmask(curl, CURLOPT_PROXY_SSL_OPTIONS, mask);
    }
  }

  if(config->path_as_is)
    my_setopt(curl, CURLOPT_PATH_AS_IS, 1L);

  if(config->no_body || config->remote_time) {
    /* no body or use remote time */
    my_setopt(curl, CURLOPT_FILETIME, 1L);
  }

  my_setopt(curl, CURLOPT_CRLF, config->crlf ? 1L : 0L);
  my_setopt_slist(curl, CURLOPT_QUOTE, config->quote);
  my_setopt_slist(curl, CURLOPT_POSTQUOTE, config->postquote);
  my_setopt_slist(curl, CURLOPT_PREQUOTE, config->prequote);

  if(config->cookies) {
    struct curlx_dynbuf cookies;
    struct curl_slist *cl;

    /* The maximum size needs to match MAX_NAME in cookie.h */
#define MAX_COOKIE_LINE 8200
    curlx_dyn_init(&cookies, MAX_COOKIE_LINE);
    for(cl = config->cookies; cl; cl = cl->next) {
      if(cl == config->cookies)
        result = curlx_dyn_addf(&cookies, "%s", cl->data);
      else
        result = curlx_dyn_addf(&cookies, ";%s", cl->data);

      if(result) {
        warnf(global,
              "skipped provided cookie, the cookie header "
              "would go over %u bytes", MAX_COOKIE_LINE);
        return result;
      }
    }

    my_setopt_str(curl, CURLOPT_COOKIE, curlx_dyn_ptr(&cookies));
    curlx_dyn_free(&cookies);
  }

  if(config->cookiefiles) {
    struct curl_slist *cfl;

    for(cfl = config->cookiefiles; cfl; cfl = cfl->next)
      my_setopt_str(curl, CURLOPT_COOKIEFILE, cfl->data);
  }

  /* new in libcurl 7.9 */
  if(config->cookiejar)
    my_setopt_str(curl, CURLOPT_COOKIEJAR, config->cookiejar);

  /* new in libcurl 7.9.7 */
  my_setopt(curl, CURLOPT_COOKIESESSION, config->cookiesession ?
            1L : 0L);

  my_setopt_enum(curl, CURLOPT_TIMECONDITION, (long)config->timecond);
  my_setopt(curl, CURLOPT_TIMEVALUE_LARGE, config->condtime);
  my_setopt_str(curl, CURLOPT_CUSTOMREQUEST, config->customrequest);
  customrequest_helper(config, config->httpreq, config->customrequest);
  my_setopt(curl, CURLOPT_STDERR, tool_stderr);

  /* three new ones in libcurl 7.3: */
  my_setopt_str(curl, CURLOPT_INTERFACE, config->iface);
  my_setopt_str(curl, CURLOPT_KRBLEVEL, config->krblevel);
  progressbarinit(&per->progressbar, config);

  if((global->progressmode == CURL_PROGRESS_BAR) &&
     !global->noprogress && !global->silent) {
    /* we want the alternative style, then we have to implement it
       ourselves! */
    my_setopt(curl, CURLOPT_XFERINFOFUNCTION, tool_progress_cb);
    my_setopt(curl, CURLOPT_XFERINFODATA, per);
  }
  else if(per->uploadfile && !strcmp(per->uploadfile, ".")) {
    /* when reading from stdin in non-blocking mode, we use the progress
       function to unpause a busy read */
    my_setopt(curl, CURLOPT_NOPROGRESS, 0L);
    my_setopt(curl, CURLOPT_XFERINFOFUNCTION, tool_readbusy_cb);
    my_setopt(curl, CURLOPT_XFERINFODATA, per);
  }

  /* new in libcurl 7.24.0: */
  if(config->dns_servers)
    my_setopt_str(curl, CURLOPT_DNS_SERVERS, config->dns_servers);

  /* new in libcurl 7.33.0: */
  if(config->dns_interface)
    my_setopt_str(curl, CURLOPT_DNS_INTERFACE, config->dns_interface);
  if(config->dns_ipv4_addr)
    my_setopt_str(curl, CURLOPT_DNS_LOCAL_IP4, config->dns_ipv4_addr);
  if(config->dns_ipv6_addr)
    my_setopt_str(curl, CURLOPT_DNS_LOCAL_IP6, config->dns_ipv6_addr);

  /* new in libcurl 7.6.2: */
  my_setopt_slist(curl, CURLOPT_TELNETOPTIONS, config->telnet_options);

  /* new in libcurl 7.7: */
  my_setopt(curl, CURLOPT_CONNECTTIMEOUT_MS, config->connecttimeout_ms);

  if(config->doh_url)
    my_setopt_str(curl, CURLOPT_DOH_URL, config->doh_url);

  if(config->cipher_list) {
    result = res_setopt_str(curl, CURLOPT_SSL_CIPHER_LIST,
                            config->cipher_list);
    if(result == CURLE_NOT_BUILT_IN)
      warnf(global, "ignoring %s, not supported by libcurl with %s",
            "--ciphers", ssl_backend());
  }
  if(config->proxy_cipher_list) {
    result = res_setopt_str(curl, CURLOPT_PROXY_SSL_CIPHER_LIST,
                            config->proxy_cipher_list);
    if(result == CURLE_NOT_BUILT_IN)
      warnf(global, "ignoring %s, not supported by libcurl with %s",
            "--proxy-ciphers", ssl_backend());
  }
  if(config->cipher13_list) {
    result = res_setopt_str(curl, CURLOPT_TLS13_CIPHERS,
                            config->cipher13_list);
    if(result == CURLE_NOT_BUILT_IN)
      warnf(global, "ignoring %s, not supported by libcurl with %s",
            "--tls13-ciphers", ssl_backend());
  }
  if(config->proxy_cipher13_list) {
    result = res_setopt_str(curl, CURLOPT_PROXY_TLS13_CIPHERS,
                            config->proxy_cipher13_list);
    if(result == CURLE_NOT_BUILT_IN)
      warnf(global, "ignoring %s, not supported by libcurl with %s",
            "--proxy-tls13-ciphers", ssl_backend());
  }

  /* new in libcurl 7.9.2: */
  if(config->disable_epsv)
    /* disable it */
    my_setopt(curl, CURLOPT_FTP_USE_EPSV, 0L);

  /* new in libcurl 7.10.5 */
  if(config->disable_eprt)
    /* disable it */
    my_setopt(curl, CURLOPT_FTP_USE_EPRT, 0L);

  if(global->tracetype != TRACE_NONE) {
    my_setopt(curl, CURLOPT_DEBUGFUNCTION, tool_debug_cb);
    my_setopt(curl, CURLOPT_DEBUGDATA, config);
    my_setopt(curl, CURLOPT_VERBOSE, 1L);
  }

  /* new in curl 7.9.3 */
  if(config->engine) {
    result = res_setopt_str(curl, CURLOPT_SSLENGINE, config->engine);
    if(result)
      return result;
  }

  /* new in curl 7.10.7, extended in 7.19.4. Modified to use
     CREATE_DIR_RETRY in 7.49.0 */
  my_setopt(curl, CURLOPT_FTP_CREATE_MISSING_DIRS,
            (long)(config->ftp_create_dirs ?
                   CURLFTP_CREATE_DIR_RETRY : CURLFTP_CREATE_DIR_NONE));

  /* new in curl 7.10.8 */
  if(config->max_filesize)
    my_setopt(curl, CURLOPT_MAXFILESIZE_LARGE,
              config->max_filesize);

  my_setopt(curl, CURLOPT_IPRESOLVE, config->ip_version);

  /* new in curl 7.15.5 */
  if(config->ftp_ssl_reqd)
    my_setopt_enum(curl, CURLOPT_USE_SSL, (long)CURLUSESSL_ALL);

  /* new in curl 7.11.0 */
  else if(config->ftp_ssl)
    my_setopt_enum(curl, CURLOPT_USE_SSL, (long)CURLUSESSL_TRY);

  /* new in curl 7.16.0 */
  else if(config->ftp_ssl_control)
    my_setopt_enum(curl, CURLOPT_USE_SSL, (long)CURLUSESSL_CONTROL);

  /* new in curl 7.16.1 */
  if(config->ftp_ssl_ccc)
    my_setopt_enum(curl, CURLOPT_FTP_SSL_CCC,
                   (long)config->ftp_ssl_ccc_mode);

  /* new in curl 7.19.4 */
  if(config->socks5_gssapi_nec)
    my_setopt_str(curl, CURLOPT_SOCKS5_GSSAPI_NEC, 1L);

  /* new in curl 7.55.0 */
  if(config->socks5_auth)
    my_setopt_bitmask(curl, CURLOPT_SOCKS5_AUTH,
                      (long)config->socks5_auth);

  /* new in curl 7.43.0 */
  if(config->proxy_service_name)
    my_setopt_str(curl, CURLOPT_PROXY_SERVICE_NAME,
                  config->proxy_service_name);

  /* new in curl 7.43.0 */
  if(config->service_name)
    my_setopt_str(curl, CURLOPT_SERVICE_NAME,
                  config->service_name);

  /* curl 7.13.0 */
  my_setopt_str(curl, CURLOPT_FTP_ACCOUNT, config->ftp_account);
  my_setopt(curl, CURLOPT_IGNORE_CONTENT_LENGTH, config->ignorecl ?
            1L : 0L);

  /* curl 7.14.2 */
  my_setopt(curl, CURLOPT_FTP_SKIP_PASV_IP, config->ftp_skip_ip ?
            1L : 0L);

  /* curl 7.15.1 */
  if(proto_ftp)
    my_setopt(curl, CURLOPT_FTP_FILEMETHOD,
              (long)config->ftp_filemethod);

  /* curl 7.15.2 */
  if(config->localport) {
    my_setopt(curl, CURLOPT_LOCALPORT, config->localport);
    my_setopt_str(curl, CURLOPT_LOCALPORTRANGE, config->localportrange);
  }

  /* curl 7.15.5 */
  my_setopt_str(curl, CURLOPT_FTP_ALTERNATIVE_TO_USER,
                config->ftp_alternative_to_user);

  /* curl 7.16.0 */
  if(config->disable_sessionid)
    /* disable it */
    my_setopt(curl, CURLOPT_SSL_SESSIONID_CACHE, 0L);

  /* curl 7.16.2 */
  if(config->raw) {
    my_setopt(curl, CURLOPT_HTTP_CONTENT_DECODING, 0L);
    my_setopt(curl, CURLOPT_HTTP_TRANSFER_DECODING, 0L);
  }

  /* curl 7.17.1 */
  if(!config->nokeepalive) {
    my_setopt(curl, CURLOPT_TCP_KEEPALIVE, 1L);
    if(config->alivetime) {
      my_setopt(curl, CURLOPT_TCP_KEEPIDLE, config->alivetime);
      my_setopt(curl, CURLOPT_TCP_KEEPINTVL, config->alivetime);
    }
    if(config->alivecnt)
      my_setopt(curl, CURLOPT_TCP_KEEPCNT, config->alivecnt);
  }
  else
    my_setopt(curl, CURLOPT_TCP_KEEPALIVE, 0L);

  /* curl 7.20.0 */
  if(config->tftp_blksize && proto_tftp)
    my_setopt(curl, CURLOPT_TFTP_BLKSIZE, config->tftp_blksize);

  if(config->mail_from)
    my_setopt_str(curl, CURLOPT_MAIL_FROM, config->mail_from);

  if(config->mail_rcpt)
    my_setopt_slist(curl, CURLOPT_MAIL_RCPT, config->mail_rcpt);

  /* curl 7.69.x */
  my_setopt(curl, CURLOPT_MAIL_RCPT_ALLOWFAILS,
            config->mail_rcpt_allowfails ? 1L : 0L);

  /* curl 7.20.x */
  if(config->ftp_pret)
    my_setopt(curl, CURLOPT_FTP_USE_PRET, 1L);

  if(config->create_file_mode)
    my_setopt(curl, CURLOPT_NEW_FILE_PERMS, config->create_file_mode);

  if(config->proto_present)
    my_setopt_str(curl, CURLOPT_PROTOCOLS_STR, config->proto_str);
  if(config->proto_redir_present)
    my_setopt_str(curl, CURLOPT_REDIR_PROTOCOLS_STR,
                  config->proto_redir_str);

  my_setopt(curl, CURLOPT_HEADERFUNCTION, tool_header_cb);
  my_setopt(curl, CURLOPT_HEADERDATA, per);

  if(config->resolve)
    /* new in 7.21.3 */
    my_setopt_slist(curl, CURLOPT_RESOLVE, config->resolve);

  if(config->connect_to)
    /* new in 7.49.0 */
    my_setopt_slist(curl, CURLOPT_CONNECT_TO, config->connect_to);

  /* new in 7.21.4 */
  if(feature_tls_srp) {
    if(config->tls_username)
      my_setopt_str(curl, CURLOPT_TLSAUTH_USERNAME,
                    config->tls_username);
    if(config->tls_password)
      my_setopt_str(curl, CURLOPT_TLSAUTH_PASSWORD,
                    config->tls_password);
    if(config->tls_authtype)
      my_setopt_str(curl, CURLOPT_TLSAUTH_TYPE,
                    config->tls_authtype);
    if(config->proxy_tls_username)
      my_setopt_str(curl, CURLOPT_PROXY_TLSAUTH_USERNAME,
                    config->proxy_tls_username);
    if(config->proxy_tls_password)
      my_setopt_str(curl, CURLOPT_PROXY_TLSAUTH_PASSWORD,
                    config->proxy_tls_password);
    if(config->proxy_tls_authtype)
      my_setopt_str(curl, CURLOPT_PROXY_TLSAUTH_TYPE,
                    config->proxy_tls_authtype);
  }

  /* new in 7.22.0 */
  if(config->gssapi_delegation)
    my_setopt_str(curl, CURLOPT_GSSAPI_DELEGATION,
                  config->gssapi_delegation);

  if(config->mail_auth)
    my_setopt_str(curl, CURLOPT_MAIL_AUTH, config->mail_auth);

  /* new in 7.66.0 */
  if(config->sasl_authzid)
    my_setopt_str(curl, CURLOPT_SASL_AUTHZID, config->sasl_authzid);

  /* new in 7.31.0 */
  if(config->sasl_ir)
    my_setopt(curl, CURLOPT_SASL_IR, 1L);

  if(config->noalpn) {
    my_setopt(curl, CURLOPT_SSL_ENABLE_ALPN, 0L);
  }

  /* new in 7.40.0, abstract support added in 7.53.0 */
  if(config->unix_socket_path) {
    if(config->abstract_unix_socket) {
      my_setopt_str(curl, CURLOPT_ABSTRACT_UNIX_SOCKET,
                    config->unix_socket_path);
    }
    else {
      my_setopt_str(curl, CURLOPT_UNIX_SOCKET_PATH,
                    config->unix_socket_path);
    }
  }

  /* new in 7.45.0 */
  if(config->proto_default)
    my_setopt_str(curl, CURLOPT_DEFAULT_PROTOCOL, config->proto_default);

  /* new in 7.47.0 */
  if(config->expect100timeout_ms > 0)
    my_setopt_str(curl, CURLOPT_EXPECT_100_TIMEOUT_MS,
                  config->expect100timeout_ms);

  /* new in 7.48.0 */
  if(config->tftp_no_options && proto_tftp)
    my_setopt(curl, CURLOPT_TFTP_NO_OPTIONS, 1L);

  /* new in 7.59.0 */
  if(config->happy_eyeballs_timeout_ms != CURL_HET_DEFAULT)
    my_setopt(curl, CURLOPT_HAPPY_EYEBALLS_TIMEOUT_MS,
              config->happy_eyeballs_timeout_ms);

  /* new in 7.60.0 */
  if(config->haproxy_protocol)
    my_setopt(curl, CURLOPT_HAPROXYPROTOCOL, 1L);

  /* new in 8.2.0 */
  if(config->haproxy_clientip)
    my_setopt_str(curl, CURLOPT_HAPROXY_CLIENT_IP,
                  config->haproxy_clientip);

  if(config->disallow_username_in_url)
    my_setopt(curl, CURLOPT_DISALLOW_USERNAME_IN_URL, 1L);

  if(config->altsvc)
    my_setopt_str(curl, CURLOPT_ALTSVC, config->altsvc);

  if(config->hsts)
    my_setopt_str(curl, CURLOPT_HSTS, config->hsts);

  if(feature_ech) {
    /* only if enabled in libcurl */
    if(config->ech) /* only if set (optional) */
      my_setopt_str(curl, CURLOPT_ECH, config->ech);
    if(config->ech_public) /* only if set (optional) */
      my_setopt_str(curl, CURLOPT_ECH, config->ech_public);
    if(config->ech_config) /* only if set (optional) */
      my_setopt_str(curl, CURLOPT_ECH, config->ech_config);
  }

  /* new in 8.9.0 */
  if(config->ip_tos > 0 || config->vlan_priority > 0) {
#if defined(IP_TOS) || defined(IPV6_TCLASS) || defined(SO_PRIORITY)
    my_setopt(curl, CURLOPT_SOCKOPTFUNCTION, sockopt_callback);
    my_setopt(curl, CURLOPT_SOCKOPTDATA, config);
#else
    if(config->ip_tos > 0) {
      errorf(config->global,
             "Type of service is not supported in this build.");
      result = CURLE_NOT_BUILT_IN;
    }
    if(config->vlan_priority > 0) {
      errorf(config->global,
             "VLAN priority is not supported in this build.");
      result = CURLE_NOT_BUILT_IN;
    }
#endif
  }
  return result;
}

static CURLcode append2query(struct GlobalConfig *global,
                             struct OperationConfig *config,
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
      errorf(global, "(%d) Could not parse the URL, "
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
        Curl_safefree(per->url); /* free previous URL */
        per->url = updated; /* use our new URL instead! */
      }
    }
    curl_url_cleanup(uh);
  }
  return result;
}

/* create the next (singular) transfer */
static CURLcode single_transfer(struct GlobalConfig *global,
                                struct OperationConfig *config,
                                CURLSH *share,
                                bool capath_from_env,
                                bool *added,
                                bool *skipped)
{
  CURLcode result = CURLE_OK;
  struct getout *urlnode;
  bool orig_noprogress = global->noprogress;
  bool orig_isatty = global->isatty;
  struct State *state = &config->state;
  char *httpgetfields = state->httpgetfields;

  *skipped = *added = FALSE; /* not yet */

  if(config->postfields) {
    if(config->use_httpget) {
      if(!httpgetfields) {
        /* Use the postfields data for an HTTP get */
        httpgetfields = state->httpgetfields = config->postfields;
        config->postfields = NULL;
        if(SetHTTPrequest(config, (config->no_body ? TOOL_HTTPREQ_HEAD :
                                   TOOL_HTTPREQ_GET), &config->httpreq)) {
          result = CURLE_FAILED_INIT;
        }
      }
    }
    else {
      if(SetHTTPrequest(config, TOOL_HTTPREQ_SIMPLEPOST, &config->httpreq))
        result = CURLE_FAILED_INIT;
    }
    if(result)
      goto fail;
  }
  if(!state->urlnode) {
    /* first time caller, setup things */
    state->urlnode = config->url_list;
    state->infilenum = 1;
  }

  result = set_cert_types(config);
  if(result)
    goto fail;

  for(; state->urlnode; state->urlnode = urlnode->next) {
    static bool warn_more_options = FALSE;
    curl_off_t urlnum;

    urlnode = state->urlnode;
    /* urlnode->url is the full URL or NULL */
    if(!urlnode->url) {
      /* This node has no URL. Free node data without destroying the
         node itself nor modifying next pointer and continue to next */
      urlnode->flags = 0;
      state->up = 0;
      if(!warn_more_options) {
        /* only show this once */
        warnf(config->global, "Got more output options than URLs");
        warn_more_options = TRUE;
      }
      continue; /* next URL please */
    }

    /* save outfile pattern before expansion */
    if(urlnode->outfile && !state->outfiles) {
      state->outfiles = strdup(urlnode->outfile);
      if(!state->outfiles) {
        errorf(global, "out of memory");
        result = CURLE_OUT_OF_MEMORY;
        break;
      }
    }

    if(!config->globoff && urlnode->infile && !state->inglob) {
      /* Unless explicitly shut off */
      result = glob_url(&state->inglob, urlnode->infile, &state->infilenum,
                        (!global->silent || global->showerror) ?
                        tool_stderr : NULL);
      if(result)
        break;
    }


    if(state->up || urlnode->infile) {
      if(!state->uploadfile) {
        if(state->inglob) {
          result = glob_next_url(&state->uploadfile, state->inglob);
          if(result == CURLE_OUT_OF_MEMORY)
            errorf(global, "out of memory");
        }
        else if(!state->up) {
          /* copy the allocated string */
          state->uploadfile = urlnode->infile;
          urlnode->infile = NULL;
        }
      }
      if(result)
        break;
    }

    if(!state->urlnum) {
      if(!config->globoff) {
        /* Unless explicitly shut off, we expand '{...}' and '[...]'
           expressions and return total number of URLs in pattern set */
        result = glob_url(&state->urls, urlnode->url, &state->urlnum,
                          (!global->silent || global->showerror) ?
                          tool_stderr : NULL);
        if(result)
          break;
        urlnum = state->urlnum;
      }
      else
        urlnum = 1; /* without globbing, this is a single URL */
    }
    else
      urlnum = state->urlnum;

    if(state->up < state->infilenum) {
      struct per_transfer *per = NULL;
      struct OutStruct *outs;
      struct OutStruct *heads;
      struct OutStruct *etag_save;
      struct HdrCbData *hdrcbdata = NULL;
      struct OutStruct etag_first;
      CURL *curl;

      /* --etag-save */
      memset(&etag_first, 0, sizeof(etag_first));
      etag_save = &etag_first;
      etag_save->stream = stdout;

      /* --etag-compare */
      if(config->etag_compare_file) {
        char *etag_from_file = NULL;
        char *header = NULL;
        ParameterError pe;

        /* open file for reading: */
        FILE *file = fopen(config->etag_compare_file, FOPEN_READTEXT);
        if(!file)
          warnf(global, "Failed to open %s: %s", config->etag_compare_file,
                strerror(errno));

        if((PARAM_OK == file2string(&etag_from_file, file)) &&
           etag_from_file) {
          header = aprintf("If-None-Match: %s", etag_from_file);
          Curl_safefree(etag_from_file);
        }
        else
          header = aprintf("If-None-Match: \"\"");

        if(!header) {
          if(file)
            fclose(file);
          errorf(global,
                 "Failed to allocate memory for custom etag header");
          result = CURLE_OUT_OF_MEMORY;
          break;
        }

        /* add Etag from file to list of custom headers */
        pe = add2list(&config->headers, header);
        Curl_safefree(header);

        if(file)
          fclose(file);
        if(pe != PARAM_OK) {
          result = CURLE_OUT_OF_MEMORY;
          break;
        }
      }

      if(config->etag_save_file) {
        if(config->create_dirs) {
          result = create_dir_hierarchy(config->etag_save_file, global);
          if(result)
            break;
        }

        /* open file for output: */
        if(strcmp(config->etag_save_file, "-")) {
          FILE *newfile = fopen(config->etag_save_file, "ab");
          if(!newfile) {
            warnf(global, "Failed creating file for saving etags: \"%s\". "
                  "Skip this transfer", config->etag_save_file);
            Curl_safefree(state->outfiles);
            glob_cleanup(&state->urls);
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
          CURL_SET_BINMODE(etag_save->stream);
        }
      }

      curl = curl_easy_init();
      if(curl)
        result = add_per_transfer(&per);
      else
        result = CURLE_OUT_OF_MEMORY;
      if(result) {
        curl_easy_cleanup(curl);
        if(etag_save->fopened)
          fclose(etag_save->stream);
        break;
      }
      per->etag_save = etag_first; /* copy the whole struct */
      if(state->uploadfile) {
        per->uploadfile = strdup(state->uploadfile);
        if(!per->uploadfile) {
          curl_easy_cleanup(curl);
          result = CURLE_OUT_OF_MEMORY;
          break;
        }
        if(SetHTTPrequest(config, TOOL_HTTPREQ_PUT, &config->httpreq)) {
          Curl_safefree(per->uploadfile);
          curl_easy_cleanup(curl);
          result = CURLE_FAILED_INIT;
          break;
        }
      }
      *added = TRUE;
      per->config = config;
      per->curl = curl;
      per->urlnum = (unsigned int)urlnode->num;

      /* default headers output stream is stdout */
      heads = &per->heads;
      heads->stream = stdout;

      /* Single header file for all URLs */
      if(config->headerfile) {
        /* open file for output: */
        if(!strcmp(config->headerfile, "%")) {
          heads->stream = stderr;
          /* use binary mode for protocol header output */
          CURL_SET_BINMODE(heads->stream);
        }
        else if(strcmp(config->headerfile, "-")) {
          FILE *newfile;

          /*
           * Since every transfer has its own file handle for dumping
           * the headers, we need to open it in append mode, since transfers
           * might finish in any order.
           * The first transfer just clears the file.
           * TODO: Consider placing the file handle inside the
           * OperationConfig, so that it does not need to be opened/closed
           * for every transfer.
           */
          if(config->create_dirs) {
            result = create_dir_hierarchy(config->headerfile, global);
            /* create_dir_hierarchy shows error upon CURLE_WRITE_ERROR */
            if(result)
              break;
          }
          if(!per->prev || per->prev->config != config) {
            newfile = fopen(config->headerfile, "wb");
            if(newfile)
              fclose(newfile);
          }
          newfile = fopen(config->headerfile, "ab");

          if(!newfile) {
            errorf(global, "Failed to open %s", config->headerfile);
            result = CURLE_WRITE_ERROR;
            break;
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
          CURL_SET_BINMODE(heads->stream);
        }
      }

      hdrcbdata = &per->hdrcbdata;

      outs = &per->outs;

      per->outfile = NULL;
      per->infdopen = FALSE;
      per->infd = STDIN_FILENO;

      /* default output stream is stdout */
      outs->stream = stdout;

      if(state->urls) {
        result = glob_next_url(&per->url, state->urls);
        if(result)
          break;
      }
      else if(!state->li) {
        per->url = strdup(urlnode->url);
        if(!per->url) {
          result = CURLE_OUT_OF_MEMORY;
          break;
        }
      }
      else
        per->url = NULL;
      if(!per->url)
        break;

      if(state->outfiles) {
        per->outfile = strdup(state->outfiles);
        if(!per->outfile) {
          result = CURLE_OUT_OF_MEMORY;
          break;
        }
      }

      if(((urlnode->flags&GETOUT_USEREMOTE) ||
          (per->outfile && strcmp("-", per->outfile)))) {

        /*
         * We have specified a filename to store the result in, or we have
         * decided we want to use the remote filename.
         */

        if(!per->outfile) {
          /* extract the filename from the URL */
          result = get_url_file_name(global, &per->outfile, per->url);
          if(result) {
            errorf(global, "Failed to extract a filename"
                   " from the URL to use for storage");
            break;
          }
        }
        else if(state->urls) {
          /* fill '#1' ... '#9' terms from URL pattern */
          char *storefile = per->outfile;
          result = glob_match_url(&per->outfile, storefile, state->urls);
          Curl_safefree(storefile);
          if(result) {
            /* bad globbing */
            warnf(global, "bad output glob");
            break;
          }
          if(!*per->outfile) {
            warnf(global, "output glob produces empty string");
            result = CURLE_WRITE_ERROR;
            break;
          }
        }
        DEBUGASSERT(per->outfile);

        if(config->output_dir && *config->output_dir) {
          char *d = aprintf("%s/%s", config->output_dir, per->outfile);
          if(!d) {
            result = CURLE_WRITE_ERROR;
            break;
          }
          free(per->outfile);
          per->outfile = d;
        }
        /* Create the directory hierarchy, if not pre-existent to a multiple
           file output call */

        if(config->create_dirs) {
          result = create_dir_hierarchy(per->outfile, global);
          /* create_dir_hierarchy shows error upon CURLE_WRITE_ERROR */
          if(result)
            break;
        }

        if(config->skip_existing) {
          struct_stat fileinfo;
          if(!stat(per->outfile, &fileinfo)) {
            /* file is present */
            notef(global, "skips transfer, \"%s\" exists locally",
                  per->outfile);
            per->skip = TRUE;
            *skipped = TRUE;
          }
        }
        if((urlnode->flags & GETOUT_USEREMOTE)
           && config->content_disposition) {
          /* Our header callback MIGHT set the filename */
          DEBUGASSERT(!outs->filename);
        }

        if(config->resume_from_current) {
          /* We are told to continue from where we are now. Get the size
             of the file as it is now and open it for append instead */
          struct_stat fileinfo;
          /* VMS -- Danger, the filesize is only valid for stream files */
          if(0 == stat(per->outfile, &fileinfo))
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
            errorf(global, "cannot open '%s'", per->outfile);
            result = CURLE_WRITE_ERROR;
            break;
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
      }

      if(per->uploadfile && !stdin_upload(per->uploadfile)) {
        /*
         * We have specified a file to upload and it is not "-".
         */
        result = add_file_name_to_url(per->curl, &per->url,
                                      per->uploadfile);
        if(result)
          break;
      }
      else if(per->uploadfile && stdin_upload(per->uploadfile)) {
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
          warnf(global,
                "Using --anyauth or --proxy-anyauth with upload from stdin"
                " involves a big risk of it not working. Use a temporary"
                " file or a fixed auth type instead");
        }

        DEBUGASSERT(per->infdopen == FALSE);
        DEBUGASSERT(per->infd == STDIN_FILENO);

        CURL_SET_BINMODE(stdin);
        if(!strcmp(per->uploadfile, ".")) {
          if(curlx_nonblock((curl_socket_t)per->infd, TRUE) < 0)
            warnf(global,
                  "fcntl failed on fd=%d: %s", per->infd, strerror(errno));
        }
      }

      if(per->uploadfile && config->resume_from_current)
        config->resume_from = -1; /* -1 will then force get-it-yourself */

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
        result = append2query(global, config, per,
                              httpgetfields ? httpgetfields : config->query);
        if(result)
          break;
      }

      if((!per->outfile || !strcmp(per->outfile, "-")) &&
         !config->use_ascii) {
        /* We get the output to stdout and we have not got the ASCII/text
           flag, then set stdout to be binary */
        CURL_SET_BINMODE(stdout);
      }

      /* explicitly passed to stdout means okaying binary gunk */
      config->terminal_binary_ok =
        (per->outfile && !strcmp(per->outfile, "-"));

      if(config->content_disposition && (urlnode->flags & GETOUT_USEREMOTE))
        hdrcbdata->honor_cd_filename = TRUE;
      else
        hdrcbdata->honor_cd_filename = FALSE;

      hdrcbdata->outs = outs;
      hdrcbdata->heads = heads;
      hdrcbdata->etag_save = etag_save;
      hdrcbdata->global = global;
      hdrcbdata->config = config;

      result = config2setopts(global, config, per, capath_from_env,
                              curl, share);
      if(result)
        break;

      /* initialize retry vars for loop below */
      per->retry_sleep_default = (config->retry_delay) ?
        config->retry_delay*1000L : RETRY_SLEEP_DEFAULT; /* ms */
      per->retry_remaining = config->req_retry;
      per->retry_sleep = per->retry_sleep_default; /* ms */
      per->retrystart = tvnow();

      state->li++;
      /* Here's looping around each globbed URL */
      if(state->li >= urlnum) {
        state->li = 0;
        state->urlnum = 0; /* forced reglob of URLs */
        glob_cleanup(&state->urls);
        state->up++;
        Curl_safefree(state->uploadfile); /* clear it to get the next */
      }
    }
    else {
      /* Free this URL node data without destroying the
         node itself nor modifying next pointer. */
      urlnode->flags = 0;
      glob_cleanup(&state->urls);
      state->urlnum = 0;

      Curl_safefree(state->outfiles);
      Curl_safefree(state->uploadfile);
      /* Free list of globbed upload files */
      glob_cleanup(&state->inglob);
      state->up = 0;
      continue;
    }
    break;
  }
  Curl_safefree(state->outfiles);
fail:
  if(!*added || result) {
    *added = FALSE;
    single_transfer_cleanup(config);
  }
  return result;
}

static long all_added; /* number of easy handles currently added */

/*
 * add_parallel_transfers() sets 'morep' to TRUE if there are more transfers
 * to add even after this call returns. sets 'addedp' to TRUE if one or more
 * transfers were added.
 */
static CURLcode add_parallel_transfers(struct GlobalConfig *global,
                                       CURLM *multi,
                                       CURLSH *share,
                                       bool *morep,
                                       bool *addedp)
{
  struct per_transfer *per;
  CURLcode result = CURLE_OK;
  CURLMcode mcode;
  bool sleeping = FALSE;
  char *errorbuf;
  *addedp = FALSE;
  *morep = FALSE;
  if(all_pers < (global->parallel_max*2)) {
    bool skipped = FALSE;
    do {
      result = create_transfer(global, share, addedp, &skipped);
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

    result = pre_transfer(global, per);
    if(result)
      return result;

    errorbuf = malloc(CURL_ERROR_SIZE);
    if(!errorbuf)
      return CURLE_OUT_OF_MEMORY;

    /* parallel connect means that we do not set PIPEWAIT since pipewait
       will make libcurl prefer multiplexing */
    (void)curl_easy_setopt(per->curl, CURLOPT_PIPEWAIT,
                           global->parallel_connect ? 0L : 1L);
    (void)curl_easy_setopt(per->curl, CURLOPT_PRIVATE, per);
    (void)curl_easy_setopt(per->curl, CURLOPT_XFERINFOFUNCTION, xferinfo_cb);
    (void)curl_easy_setopt(per->curl, CURLOPT_XFERINFODATA, per);
    (void)curl_easy_setopt(per->curl, CURLOPT_NOPROGRESS, 0L);
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
        result = create_transfer(global, share, &getadded, &skipped);
        if(result)
          break;
      } while(skipped);
    }
    if(result) {
      free(errorbuf);
      return result;
    }
    errorbuf[0] = 0;
    (void)curl_easy_setopt(per->curl, CURLOPT_ERRORBUFFER, errorbuf);
    per->errorbuffer = errorbuf;
    per->added = TRUE;
    all_added++;
    *addedp = TRUE;
  }
  *morep = (per || sleeping);
  return CURLE_OK;
}

struct parastate {
  struct GlobalConfig *global;
  CURLM *multi;
  CURLSH *share;
  CURLMcode mcode;
  CURLcode result;
  int still_running;
  struct timeval start;
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
    result = add_parallel_transfers(uv->s->global, uv->s->multi,
                                    uv->s->share,
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
static int cb_timeout(CURLM *multi, long timeout_ms,
                      struct datauv *uv)
{
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
                     struct datauv *uv,
                     void *socketp)
{
  struct contextuv *c;
  int events = 0;
  (void)easy;

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
      result = add_parallel_transfers(s->global, s->multi, s->share,
                                      &s->more_transfers, &s->added_transfers);
      if(result && !s->result)
        s->result = result;
    }
  }

#if DEBUG_UV
  fprintf(tool_stderr, "DONE parallel_event -> %d, mcode=%d, %d running, "
          "%d more\n",
          s->result, s->mcode, uv.s->still_running, s->more_transfers);
#endif
  return s->result;
}

#endif

static CURLcode check_finished(struct parastate *s)
{
  CURLcode result = CURLE_OK;
  int rc;
  CURLMsg *msg;
  bool checkmore = FALSE;
  struct GlobalConfig *global = s->global;
  progress_meter(global, &s->start, FALSE);
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

      if(ended->abort && (tres == CURLE_ABORTED_BY_CALLBACK) &&
         ended->errorbuffer) {
        msnprintf(ended->errorbuffer, CURL_ERROR_SIZE,
                  "Transfer aborted due to critical error "
                  "in another transfer");
      }
      tres = post_per_transfer(global, ended, tres, &retry, &delay);
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
      CURLcode tres = add_parallel_transfers(global, s->multi, s->share,
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

static CURLcode parallel_transfers(struct GlobalConfig *global,
                                   CURLSH *share)
{
  CURLcode result;
  struct parastate p;
  struct parastate *s = &p;
  s->share = share;
  s->mcode = CURLM_OK;
  s->result = CURLE_OK;
  s->still_running = 1;
  s->start = tvnow();
  s->wrapitup = FALSE;
  s->wrapitup_processed = FALSE;
  s->tick = time(NULL);
  s->global = global;
  s->multi = curl_multi_init();
  if(!s->multi)
    return CURLE_OUT_OF_MEMORY;

  result = add_parallel_transfers(global, s->multi, s->share,
                                  &s->more_transfers, &s->added_transfers);
  if(result) {
    curl_multi_cleanup(s->multi);
    return result;
  }

#ifdef DEBUGBUILD
  if(global->test_event_based)
#ifdef USE_LIBUV
    result = parallel_event(s);
#else
    errorf(global, "Testing --parallel event-based requires libuv");
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

    (void)progress_meter(global, &s->start, TRUE);
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

static CURLcode serial_transfers(struct GlobalConfig *global,
                                 CURLSH *share)
{
  CURLcode returncode = CURLE_OK;
  CURLcode result = CURLE_OK;
  struct per_transfer *per;
  bool added = FALSE;
  bool skipped = FALSE;

  result = create_transfer(global, share, &added, &skipped);
  if(result)
    return result;
  if(!added) {
    errorf(global, "no transfer performed");
    return CURLE_READ_ERROR;
  }
  for(per = transfers; per;) {
    bool retry;
    long delay_ms;
    bool bailout = FALSE;
    struct timeval start;

    start = tvnow();
    if(!per->skip) {
      result = pre_transfer(global, per);
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

    returncode = post_per_transfer(global, per, result, &retry, &delay_ms);
    if(retry) {
      tool_go_sleep(delay_ms);
      continue;
    }

    /* Bail out upon critical errors or --fail-early */
    if(is_fatal_error(returncode) || (returncode && global->fail_early))
      bailout = TRUE;
    else {
      do {
        /* setup the next one just before we delete this */
        result = create_transfer(global, share, &added, &skipped);
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
      long milli = tvdiff(tvnow(), start);
      if(milli < global->ms_per_transfer) {
        notef(global, "Transfer took %ld ms, waits %ldms as set by --rate",
              milli, global->ms_per_transfer - milli);
        /* The transfer took less time than wanted. Wait a little. */
        tool_go_sleep(global->ms_per_transfer - milli);
      }
    }
  }
  if(returncode)
    /* returncode errors have priority */
    result = returncode;

  if(result)
    single_transfer_cleanup(global->current);

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
#if defined(CURL_CA_SEARCH_SAFE)
    char *cacert = NULL;
    FILE *cafile = Curl_execpath("curl-ca-bundle.crt", &cacert);
    if(cafile) {
      fclose(cafile);
      config->cacert = strdup(cacert);
    }
#elif !defined(CURL_WINDOWS_UWP) && !defined(CURL_DISABLE_CA_SEARCH)
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
static CURLcode transfer_per_config(struct GlobalConfig *global,
                                    struct OperationConfig *config,
                                    CURLSH *share,
                                    bool *added,
                                    bool *skipped)
{
  CURLcode result = CURLE_OK;
  bool capath_from_env;
  *added = FALSE;

  /* Check we have a url */
  if(!config->url_list || !config->url_list->url) {
    helpf(tool_stderr, "(%d) no URL specified", CURLE_FAILED_INIT);
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
  capath_from_env = false;
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

  if(!result)
    result = single_transfer(global, config, share, capath_from_env, added,
                             skipped);

  return result;
}

/*
 * 'create_transfer' gets the details and sets up a new transfer if 'added'
 * returns TRUE.
 */
static CURLcode create_transfer(struct GlobalConfig *global,
                                CURLSH *share,
                                bool *added,
                                bool *skipped)
{
  CURLcode result = CURLE_OK;
  *added = FALSE;
  while(global->current) {
    result = transfer_per_config(global, global->current, share, added,
                                 skipped);
    if(!result && !*added) {
      /* when one set is drained, continue to next */
      global->current = global->current->next;
      continue;
    }
    break;
  }
  return result;
}

static CURLcode run_all_transfers(struct GlobalConfig *global,
                                  CURLSH *share,
                                  CURLcode result)
{
  /* Save the values of noprogress and isatty to restore them later on */
  bool orig_noprogress = global->noprogress;
  bool orig_isatty = global->isatty;
  struct per_transfer *per;

  /* Time to actually do the transfers */
  if(!result) {
    if(global->parallel)
      result = parallel_transfers(global, share);
    else
      result = serial_transfers(global, share);
  }

  /* cleanup if there are any left */
  for(per = transfers; per;) {
    bool retry;
    long delay;
    CURLcode result2 = post_per_transfer(global, per, result, &retry, &delay);
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

CURLcode operate(struct GlobalConfig *global, int argc, argv_item_t argv[])
{
  CURLcode result = CURLE_OK;
  char *first_arg = argc > 1 ? curlx_convert_tchar_to_UTF8(argv[1]) : NULL;

#ifdef HAVE_SETLOCALE
  /* Override locale for number parsing (only) */
  setlocale(LC_ALL, "");
  setlocale(LC_NUMERIC, "C");
#endif

  /* Parse .curlrc if necessary */
  if((argc == 1) ||
     (first_arg && strncmp(first_arg, "-q", 2) &&
      strcmp(first_arg, "--disable"))) {
    parseconfig(NULL, global); /* ignore possible failure */

    /* If we had no arguments then make sure a url was specified in .curlrc */
    if((argc < 2) && (!global->first->url_list)) {
      helpf(tool_stderr, NULL);
      result = CURLE_FAILED_INIT;
    }
  }

  curlx_unicodefree(first_arg);

  if(!result) {
    /* Parse the command line arguments */
    ParameterError res = parse_args(global, argc, argv);
    if(res) {
      result = CURLE_OK;

      /* Check if we were asked for the help */
      if(res == PARAM_HELP_REQUESTED)
        tool_help(global->help_category);
      /* Check if we were asked for the manual */
      else if(res == PARAM_MANUAL_REQUESTED) {
#ifdef USE_MANUAL
        hugehelp();
#else
        puts("built-in manual was disabled at build-time");
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
          curl_share_setopt(share, CURLSHOPT_SHARE, CURL_LOCK_DATA_CONNECT);
          curl_share_setopt(share, CURLSHOPT_SHARE, CURL_LOCK_DATA_PSL);
          curl_share_setopt(share, CURLSHOPT_SHARE, CURL_LOCK_DATA_HSTS);

          if(global->ssl_sessions && feature_ssls_export)
            result = tool_ssls_load(global, global->first, share,
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
            result = run_all_transfers(global, share, result);

            if(global->ssl_sessions && feature_ssls_export) {
              CURLcode r2 = tool_ssls_save(global, global->first, share,
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
            dumpeasysrc(global);
          }
        }
      }
      else
        errorf(global, "out of memory");
    }
  }

  varcleanup(global);

  return result;
}
