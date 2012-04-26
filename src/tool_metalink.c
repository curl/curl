/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2012, Daniel Stenberg, <daniel@haxx.se>, et al.
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
#include "tool_setup.h"

#ifdef HAVE_UNISTD_H
#  include <unistd.h>
#endif

#ifdef HAVE_UTIME_H
#  include <utime.h>
#elif defined(HAVE_SYS_UTIME_H)
#  include <sys/utime.h>
#endif

#define ENABLE_CURLX_PRINTF
/* use our own printf() functions */
#include "curlx.h"

#include "tool_metalink.h"
#include "tool_binmode.h"
#include "tool_cb_prg.h"
#include "tool_cb_wrt.h"
#include "tool_cb_rea.h"
#include "tool_cb_see.h"
#include "tool_cb_dbg.h"
#include "tool_dirhie.h"
#include "tool_util.h"
#include "tool_main.h"
#include "tool_msgs.h"
#include "tool_setopt.h"
#include "tool_sleep.h"
#include "tool_writeout.h"
#include "tool_libinfo.h"
#include "tool_homedir.h"
#include "tool_cb_hdr.h"

#include "memdebug.h" /* keep this as LAST include */

static int curl_truncate_file(struct Configurable *config,
                              struct OutStruct outs)
{
  int res = 0;
  if(outs.bytes && outs.filename) {
    /* We have written data to a output file, we truncate file
     */
    if(!config->mute)
      fprintf(config->errors, "Throwing away %"
              CURL_FORMAT_CURL_OFF_T " bytes\n",
              outs.bytes);
    fflush(outs.stream);
    /* truncate file at the position where we started appending */
#ifdef HAVE_FTRUNCATE
    if(ftruncate( fileno(outs.stream), outs.init)) {
      /* when truncate fails, we can't just append as then we'll
         create something strange, bail out */
      if(!config->mute)
        fprintf(config->errors,
                "failed to truncate, exiting\n");
      res = CURLE_WRITE_ERROR;
      assert(0);
      /* goto quit_urls; */
    }
    /* now seek to the end of the file, the position where we
       just truncated the file in a large file-safe way */
    fseek(outs.stream, 0, SEEK_END);
#else
    /* ftruncate is not available, so just reposition the file
       to the location we would have truncated it. This won't
       work properly with large files on 32-bit systems, but
       most of those will have ftruncate. */
    fseek(outs.stream, (long)outs.init, SEEK_SET);
#endif
    outs.bytes = 0; /* clear for next round */
  }
  return res;
}

struct metalinkfile *new_metalinkfile(metalink_file_t *metalinkfile) {
  struct metalinkfile *f;
  f = (struct metalinkfile*)malloc(sizeof(struct metalinkfile));
  f->file = metalinkfile;
  f->next = NULL;
  return f;
}

struct metalink *new_metalink(metalink_t *metalink) {
  struct metalink *ml;
  ml = (struct metalink*)malloc(sizeof(struct metalink));
  ml->metalink = metalink;
  ml->next = NULL;
  return ml;
}

int operatemetalink(CURL *curl,
                    struct getout *urlnode,
                    long retry_sleep_default,
                    struct OutStruct outs,
                    struct OutStruct heads,
                    char *outfiles,
                    struct Configurable *config)
{
  long retry_numretries;
  int infd = STDIN_FILENO;
  bool infdopen;
  char *outfile;
  struct timeval retrystart;
  struct metalinkfile *mlfile;
  int res = 0;
  char *filename;
  metalink_resource_t **mlres;
  char errorbuffer[CURL_ERROR_SIZE];
  struct ProgressData progressbar;
  long retry_sleep;
  struct InStruct input;
  curl_off_t uploadfilesize; /* -1 means unknown */
  char *uploadfile=NULL; /* a single file, never a glob */

  uploadfilesize=-1;

  mlfile = config->metalinkfile_last;
  config->metalinkfile_last = config->metalinkfile_last->next;

  filename = strdup(mlfile->file->name);

  outfile = outfiles?strdup(outfiles):NULL;

  if((urlnode->flags & GETOUT_USEREMOTE) ||
     (outfile && !curlx_strequal("-", outfile)) ) {

    /*
     * We have specified a file name to store the result in, or we have
     * decided we want to use the name attribute of file element in Metalink
     * XML.
     */

    if(!outfile) {
      /* Find and get file name */
      char * pc;
      pc = strrchr(filename, '/');

      if(pc) {
        /* duplicate the string beyond the slash */
        pc++;
        outfile = *pc ? strdup(pc): NULL;
      }
      else {
        outfile = strdup(filename);
      }

      if(!outfile || !*outfile) {
        helpf(config->errors, "Metalink file[@name] has no length!\n");
        res = CURLE_WRITE_ERROR;
        free(filename);
        /* break; */
        return 1;
      }
#if defined(MSDOS)
      {
        /* This is for DOS, and then we do some major replacing of
           bad characters in the file name before using it */
        char file1[PATH_MAX];
        if(strlen(outfile) >= PATH_MAX)
          outfile[PATH_MAX-1]=0; /* cut it */
        strcpy(file1, msdosify(outfile));
        free(outfile);

        outfile = strdup(rename_if_dos_device_name(file1));
        if(!outfile) {
          res = CURLE_OUT_OF_MEMORY;
          break;
        }
      }
#endif /* MSDOS */
    }
    /* Create the directory hierarchy, if not pre-existant to a multiple
       file output call */

    if(config->create_dirs &&
       (CURLE_WRITE_ERROR == create_dir_hierarchy(outfile, config->errors)))
      return CURLE_WRITE_ERROR;

    if(config->resume_from_current) {
      /* We're told to continue from where we are now. Get the
         size of the file as it is now and open it for append instead */

      struct_stat fileinfo;

      /* VMS -- Danger, the filesize is only valid for stream files */
      if(0 == stat(outfile, &fileinfo))
        /* set offset to current file size: */
        config->resume_from = fileinfo.st_size;
      else
        /* let offset be 0 */
        config->resume_from = 0;
    }

    outs.filename = outfile;
    outs.s_isreg = TRUE;

    if(config->resume_from) {
      outs.init = config->resume_from;
      /* open file for output: */
      outs.stream=(FILE *) fopen(outfile, config->resume_from?"ab":"wb");
      if(!outs.stream) {
        helpf(config->errors, "Can't open '%s'!\n", outfile);
        return CURLE_WRITE_ERROR;
      }
    }
    else {
      outs.stream = NULL; /* open when needed */
    }
  }
  infdopen=FALSE;

  if(!config->errors)
    config->errors = stderr;

  if(!outfile && !config->use_ascii) {
    /* We get the output to stdout and we have not got the ASCII/text
       flag, then set stdout to be binary */
    set_binmode(stdout);
  }

  /* Loop though all resources in Metalink */
  for(mlres = mlfile->file->resources; *mlres; ++mlres) {
    int try_next_res = 0;
    if(config->tcp_nodelay)
      my_setopt(curl, CURLOPT_TCP_NODELAY, 1);

    /* where to store */
    my_setopt(curl, CURLOPT_WRITEDATA, &outs);
    /* what call to write */
    my_setopt(curl, CURLOPT_WRITEFUNCTION, tool_write_cb);


    /* for uploads */
    input.fd = infd;
    input.config = config;
    /* Note that if CURLOPT_READFUNCTION is fread (the default), then
     * lib/telnet.c will Curl_poll() on the input file descriptor
     * rather then calling the READFUNCTION at regular intervals.
     * The circumstances in which it is preferable to enable this
     * behaviour, by omitting to set the READFUNCTION & READDATA options,
     * have not been determined.
     */
    my_setopt(curl, CURLOPT_READDATA, &input);
    /* what call to read */
    my_setopt(curl, CURLOPT_READFUNCTION, tool_read_cb);

    /* in 7.18.0, the CURLOPT_SEEKFUNCTION/DATA pair is taking over what
       CURLOPT_IOCTLFUNCTION/DATA pair previously provided for seeking */
    my_setopt(curl, CURLOPT_SEEKDATA, &input);
    my_setopt(curl, CURLOPT_SEEKFUNCTION, tool_seek_cb);

    if(config->recvpersecond)
      /* tell libcurl to use a smaller sized buffer as it allows us to
         make better sleeps! 7.9.9 stuff! */
      my_setopt(curl, CURLOPT_BUFFERSIZE, config->recvpersecond);

    /* size of uploaded file: */
    if(uploadfilesize != -1)
      my_setopt(curl, CURLOPT_INFILESIZE_LARGE, uploadfilesize);
    my_setopt(curl, CURLOPT_URL, (*mlres)->url);     /* what to fetch */
    my_setopt(curl, CURLOPT_NOPROGRESS, config->noprogress);
    if(config->no_body) {
      my_setopt(curl, CURLOPT_NOBODY, 1);
      my_setopt(curl, CURLOPT_HEADER, 1);
    }
    else
      my_setopt(curl, CURLOPT_HEADER, config->include_headers);

#if !defined(CURL_DISABLE_PROXY)
    {
      /* TODO: Make this a run-time check instead of compile-time one. */

      my_setopt_str(curl, CURLOPT_PROXY, config->proxy);
      my_setopt_str(curl, CURLOPT_PROXYUSERPWD, config->proxyuserpwd);

      /* new in libcurl 7.3 */
      my_setopt(curl, CURLOPT_HTTPPROXYTUNNEL, config->proxytunnel);

      /* new in libcurl 7.5 */
      if(config->proxy)
        my_setopt_enum(curl, CURLOPT_PROXYTYPE, config->proxyver);

      /* new in libcurl 7.10 */
      if(config->socksproxy) {
        my_setopt_str(curl, CURLOPT_PROXY, config->socksproxy);
        my_setopt_enum(curl, CURLOPT_PROXYTYPE, config->socksver);
      }

      /* new in libcurl 7.10.6 */
      if(config->proxyanyauth)
        my_setopt_bitmask(curl, CURLOPT_PROXYAUTH,
                          (long) CURLAUTH_ANY);
      else if(config->proxynegotiate)
        my_setopt_bitmask(curl, CURLOPT_PROXYAUTH,
                          (long) CURLAUTH_GSSNEGOTIATE);
      else if(config->proxyntlm)
        my_setopt_bitmask(curl, CURLOPT_PROXYAUTH,
                          (long) CURLAUTH_NTLM);
      else if(config->proxydigest)
        my_setopt_bitmask(curl, CURLOPT_PROXYAUTH,
                          (long) CURLAUTH_DIGEST);
      else if(config->proxybasic)
        my_setopt_bitmask(curl, CURLOPT_PROXYAUTH,
                          (long) CURLAUTH_BASIC);

      /* new in libcurl 7.19.4 */
      my_setopt(curl, CURLOPT_NOPROXY, config->noproxy);
    }
#endif

    my_setopt(curl, CURLOPT_FAILONERROR, config->failonerror);
    my_setopt(curl, CURLOPT_UPLOAD, uploadfile?TRUE:FALSE);
    my_setopt(curl, CURLOPT_DIRLISTONLY, config->dirlistonly);
    my_setopt(curl, CURLOPT_APPEND, config->ftp_append);

    if(config->netrc_opt)
      my_setopt(curl, CURLOPT_NETRC, CURL_NETRC_OPTIONAL);
    else if(config->netrc || config->netrc_file)
      my_setopt(curl, CURLOPT_NETRC, CURL_NETRC_REQUIRED);
    else
      my_setopt(curl, CURLOPT_NETRC, CURL_NETRC_IGNORED);

    if(config->netrc_file)
      my_setopt(curl, CURLOPT_NETRC_FILE, config->netrc_file);

    my_setopt(curl, CURLOPT_TRANSFERTEXT, config->use_ascii);
    my_setopt_str(curl, CURLOPT_USERPWD, config->userpwd);
    my_setopt_str(curl, CURLOPT_RANGE, config->range);
    my_setopt(curl, CURLOPT_ERRORBUFFER, errorbuffer);
    my_setopt(curl, CURLOPT_TIMEOUT, config->timeout);

    if(built_in_protos & CURLPROTO_HTTP) {

      long postRedir = 0;

      my_setopt(curl, CURLOPT_FOLLOWLOCATION,
                config->followlocation);
      my_setopt(curl, CURLOPT_UNRESTRICTED_AUTH,
                config->unrestricted_auth);

      switch(config->httpreq) {
      case HTTPREQ_SIMPLEPOST:
        my_setopt_str(curl, CURLOPT_POSTFIELDS,
                      config->postfields);
        my_setopt(curl, CURLOPT_POSTFIELDSIZE_LARGE,
                  config->postfieldsize);
        break;
      case HTTPREQ_POST:
        my_setopt_httppost(curl, CURLOPT_HTTPPOST, config->httppost);
        break;
      default:
        break;
      }

      my_setopt_str(curl, CURLOPT_REFERER, config->referer);
      my_setopt(curl, CURLOPT_AUTOREFERER, config->autoreferer);
      my_setopt_str(curl, CURLOPT_USERAGENT, config->useragent);
      my_setopt_slist(curl, CURLOPT_HTTPHEADER, config->headers);

      /* new in libcurl 7.5 */
      my_setopt(curl, CURLOPT_MAXREDIRS, config->maxredirs);

      /* new in libcurl 7.9.1 */
      if(config->httpversion)
        my_setopt_enum(curl, CURLOPT_HTTP_VERSION, config->httpversion);

      /* new in libcurl 7.10.6 (default is Basic) */
      if(config->authtype)
        my_setopt_bitmask(curl, CURLOPT_HTTPAUTH, (long) config->authtype);

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
        my_setopt(curl, CURLOPT_TRANSFER_ENCODING, 1);

    } /* (built_in_protos & CURLPROTO_HTTP) */

    my_setopt_str(curl, CURLOPT_FTPPORT, config->ftpport);
    my_setopt(curl, CURLOPT_LOW_SPEED_LIMIT,
              config->low_speed_limit);
    my_setopt(curl, CURLOPT_LOW_SPEED_TIME, config->low_speed_time);
    my_setopt(curl, CURLOPT_MAX_SEND_SPEED_LARGE,
              config->sendpersecond);
    my_setopt(curl, CURLOPT_MAX_RECV_SPEED_LARGE,
              config->recvpersecond);
    my_setopt(curl, CURLOPT_RESUME_FROM_LARGE,
              config->use_resume?config->resume_from:0);

    my_setopt(curl, CURLOPT_SSLCERT, config->cert);
    my_setopt_str(curl, CURLOPT_SSLCERTTYPE, config->cert_type);
    my_setopt(curl, CURLOPT_SSLKEY, config->key);
    my_setopt_str(curl, CURLOPT_SSLKEYTYPE, config->key_type);
    my_setopt_str(curl, CURLOPT_KEYPASSWD, config->key_passwd);

    if(built_in_protos & (CURLPROTO_SCP|CURLPROTO_SFTP)) {

      /* SSH and SSL private key uses same command-line option */
      /* new in libcurl 7.16.1 */
      my_setopt_str(curl, CURLOPT_SSH_PRIVATE_KEYFILE, config->key);
      /* new in libcurl 7.16.1 */
      my_setopt_str(curl, CURLOPT_SSH_PUBLIC_KEYFILE, config->pubkey);

      /* new in libcurl 7.17.1: SSH host key md5 checking allows us
         to fail if we are not talking to who we think we should */
      my_setopt_str(curl, CURLOPT_SSH_HOST_PUBLIC_KEY_MD5,
                    config->hostpubmd5);
    }

    if(config->cacert)
      my_setopt_str(curl, CURLOPT_CAINFO, config->cacert);
    if(config->capath)
      my_setopt_str(curl, CURLOPT_CAPATH, config->capath);
    if(config->crlfile)
      my_setopt_str(curl, CURLOPT_CRLFILE, config->crlfile);

    if(curlinfo->features & CURL_VERSION_SSL) {
      if(config->insecure_ok) {
        my_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
        my_setopt(curl, CURLOPT_SSL_VERIFYHOST, 1L);
      }
      else {
        my_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
        /* libcurl default is strict verifyhost -> 2L   */
        /* my_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L); */
      }
    }

    if(built_in_protos & (CURLPROTO_SCP|CURLPROTO_SFTP)) {
      if(!config->insecure_ok) {
        char *home;
        char *file;
        res = CURLE_OUT_OF_MEMORY;
        home = homedir();
        if(home) {
          file = aprintf("%s/%sssh/known_hosts", home, DOT_CHAR);
          if(file) {
            /* new in curl 7.19.6 */
            res = res_setopt_str(curl, CURLOPT_SSH_KNOWNHOSTS, file);
            curl_free(file);
            if(res == CURLE_UNKNOWN_OPTION)
              /* libssh2 version older than 1.1.1 */
              res = CURLE_OK;
          }
          Curl_safefree(home);
        }
        if(res)
          goto show_error;
      }
    }

    if(config->no_body || config->remote_time) {
      /* no body or use remote time */
      my_setopt(curl, CURLOPT_FILETIME, TRUE);
    }

    my_setopt(curl, CURLOPT_CRLF, config->crlf);
    my_setopt_slist(curl, CURLOPT_QUOTE, config->quote);
    my_setopt_slist(curl, CURLOPT_POSTQUOTE, config->postquote);
    my_setopt_slist(curl, CURLOPT_PREQUOTE, config->prequote);

#if !defined(CURL_DISABLE_HTTP) && !defined(CURL_DISABLE_COOKIES)
    {
      /* TODO: Make this a run-time check instead of compile-time one. */

      if(config->cookie)
        my_setopt_str(curl, CURLOPT_COOKIE, config->cookie);

      if(config->cookiefile)
        my_setopt_str(curl, CURLOPT_COOKIEFILE, config->cookiefile);

      /* new in libcurl 7.9 */
      if(config->cookiejar)
        my_setopt_str(curl, CURLOPT_COOKIEJAR, config->cookiejar);

      /* new in libcurl 7.9.7 */
      my_setopt(curl, CURLOPT_COOKIESESSION, config->cookiesession);
    }
#endif

    my_setopt_enum(curl, CURLOPT_SSLVERSION, config->ssl_version);
    my_setopt_enum(curl, CURLOPT_TIMECONDITION, config->timecond);
    my_setopt(curl, CURLOPT_TIMEVALUE, config->condtime);
    my_setopt_str(curl, CURLOPT_CUSTOMREQUEST, config->customrequest);
    my_setopt(curl, CURLOPT_STDERR, config->errors);

    /* three new ones in libcurl 7.3: */
    my_setopt_str(curl, CURLOPT_INTERFACE, config->iface);
    my_setopt_str(curl, CURLOPT_KRBLEVEL, config->krblevel);

    progressbarinit(&progressbar, config);
    if((config->progressmode == CURL_PROGRESS_BAR) &&
       !config->noprogress && !config->mute) {
      /* we want the alternative style, then we have to implement it
         ourselves! */
      my_setopt(curl, CURLOPT_PROGRESSFUNCTION, tool_progress_cb);
      my_setopt(curl, CURLOPT_PROGRESSDATA, &progressbar);
    }

    /* new in libcurl 7.6.2: */
    my_setopt_slist(curl, CURLOPT_TELNETOPTIONS, config->telnet_options);

    /* new in libcurl 7.7: */
    my_setopt_str(curl, CURLOPT_RANDOM_FILE, config->random_file);
    my_setopt(curl, CURLOPT_EGDSOCKET, config->egd_file);
    my_setopt(curl, CURLOPT_CONNECTTIMEOUT, config->connecttimeout);

    if(config->cipher_list)
      my_setopt_str(curl, CURLOPT_SSL_CIPHER_LIST, config->cipher_list);

    /* new in libcurl 7.9.2: */
    if(config->disable_epsv)
      /* disable it */
      my_setopt(curl, CURLOPT_FTP_USE_EPSV, FALSE);

    /* new in libcurl 7.10.5 */
    if(config->disable_eprt)
      /* disable it */
      my_setopt(curl, CURLOPT_FTP_USE_EPRT, FALSE);

    if(config->tracetype != TRACE_NONE) {
      my_setopt(curl, CURLOPT_DEBUGFUNCTION, tool_debug_cb);
      my_setopt(curl, CURLOPT_DEBUGDATA, config);
      my_setopt(curl, CURLOPT_VERBOSE, TRUE);
    }

    /* new in curl 7.9.3 */
    if(config->engine) {
      res = res_setopt_str(curl, CURLOPT_SSLENGINE, config->engine);
      if(res)
        goto show_error;
      my_setopt(curl, CURLOPT_SSLENGINE_DEFAULT, 1);
    }

    /* new in curl 7.10.7, extended in 7.19.4 but this only sets 0 or 1 */
    my_setopt(curl, CURLOPT_FTP_CREATE_MISSING_DIRS,
              config->ftp_create_dirs);

    /* new in curl 7.10.8 */
    if(config->max_filesize)
      my_setopt(curl, CURLOPT_MAXFILESIZE_LARGE,
                config->max_filesize);

    if(4 == config->ip_version)
      my_setopt(curl, CURLOPT_IPRESOLVE, CURL_IPRESOLVE_V4);
    else if(6 == config->ip_version)
      my_setopt(curl, CURLOPT_IPRESOLVE, CURL_IPRESOLVE_V6);
    else
      my_setopt(curl, CURLOPT_IPRESOLVE, CURL_IPRESOLVE_WHATEVER);

    /* new in curl 7.15.5 */
    if(config->ftp_ssl_reqd)
      my_setopt(curl, CURLOPT_USE_SSL, CURLUSESSL_ALL);

    /* new in curl 7.11.0 */
    else if(config->ftp_ssl)
      my_setopt(curl, CURLOPT_USE_SSL, CURLUSESSL_TRY);

    /* new in curl 7.16.0 */
    else if(config->ftp_ssl_control)
      my_setopt(curl, CURLOPT_USE_SSL, CURLUSESSL_CONTROL);

    /* new in curl 7.16.1 */
    if(config->ftp_ssl_ccc)
      my_setopt_enum(curl, CURLOPT_FTP_SSL_CCC, config->ftp_ssl_ccc_mode);

#if defined(HAVE_GSSAPI) || defined(USE_WINDOWS_SSPI)
    {
      /* TODO: Make this a run-time check instead of compile-time one. */

      /* new in curl 7.19.4 */
      if(config->socks5_gssapi_service)
        my_setopt_str(curl, CURLOPT_SOCKS5_GSSAPI_SERVICE,
                      config->socks5_gssapi_service);

      /* new in curl 7.19.4 */
      if(config->socks5_gssapi_nec)
        my_setopt_str(curl, CURLOPT_SOCKS5_GSSAPI_NEC,
                      config->socks5_gssapi_nec);
    }
#endif
    /* curl 7.13.0 */
    my_setopt_str(curl, CURLOPT_FTP_ACCOUNT, config->ftp_account);

    my_setopt(curl, CURLOPT_IGNORE_CONTENT_LENGTH, config->ignorecl);

    /* curl 7.14.2 */
    my_setopt(curl, CURLOPT_FTP_SKIP_PASV_IP, config->ftp_skip_ip);

    /* curl 7.15.1 */
    my_setopt(curl, CURLOPT_FTP_FILEMETHOD, config->ftp_filemethod);

    /* curl 7.15.2 */
    if(config->localport) {
      my_setopt(curl, CURLOPT_LOCALPORT, config->localport);
      my_setopt_str(curl, CURLOPT_LOCALPORTRANGE,
                    config->localportrange);
    }

    /* curl 7.15.5 */
    my_setopt_str(curl, CURLOPT_FTP_ALTERNATIVE_TO_USER,
                  config->ftp_alternative_to_user);

    /* curl 7.16.0 */
    if(config->disable_sessionid)
      my_setopt(curl, CURLOPT_SSL_SESSIONID_CACHE,
                !config->disable_sessionid);

    /* curl 7.16.2 */
    if(config->raw) {
      my_setopt(curl, CURLOPT_HTTP_CONTENT_DECODING, FALSE);
      my_setopt(curl, CURLOPT_HTTP_TRANSFER_DECODING, FALSE);
    }

    /* curl 7.17.1 */
    if(!config->nokeepalive) {
      my_setopt(curl, CURLOPT_TCP_KEEPALIVE, 1L);
      if(config->alivetime != 0) {
#if !defined(TCP_KEEPIDLE) || !defined(TCP_KEEPINTVL)
        warnf(config, "Keep-alive functionality somewhat crippled due to "
              "missing support in your operating system!\n");
#endif
        my_setopt(curl, CURLOPT_TCP_KEEPIDLE, config->alivetime);
        my_setopt(curl, CURLOPT_TCP_KEEPINTVL, config->alivetime);
      }
    }
    else
      my_setopt(curl, CURLOPT_TCP_KEEPALIVE, 0L);

    /* curl 7.20.0 */
    if(config->tftp_blksize)
      my_setopt(curl, CURLOPT_TFTP_BLKSIZE, config->tftp_blksize);

    if(config->mail_from)
      my_setopt_str(curl, CURLOPT_MAIL_FROM, config->mail_from);

    if(config->mail_rcpt)
      my_setopt_slist(curl, CURLOPT_MAIL_RCPT, config->mail_rcpt);

    /* curl 7.20.x */
    if(config->ftp_pret)
      my_setopt(curl, CURLOPT_FTP_USE_PRET, TRUE);

    if(config->proto_present)
      my_setopt_flags(curl, CURLOPT_PROTOCOLS, config->proto);
    if(config->proto_redir_present)
      my_setopt_flags(curl, CURLOPT_REDIR_PROTOCOLS, config->proto_redir);

    if((urlnode->flags & GETOUT_USEREMOTE)
       && config->content_disposition) {
      my_setopt(curl, CURLOPT_HEADERFUNCTION, tool_header_cb);
      my_setopt(curl, CURLOPT_HEADERDATA, &outs);
    }
    else {
      /* if HEADERFUNCTION was set to something in the previous loop, it
         is important that we set it (back) to NULL now */
      my_setopt(curl, CURLOPT_HEADERFUNCTION, NULL);
      my_setopt(curl, CURLOPT_HEADERDATA, config->headerfile?&heads:NULL);
    }

    if(config->resolve)
      /* new in 7.21.3 */
      my_setopt_slist(curl, CURLOPT_RESOLVE, config->resolve);

    /* new in 7.21.4 */
    if(curlinfo->features & CURL_VERSION_TLSAUTH_SRP) {
      if(config->tls_username)
        my_setopt_str(curl, CURLOPT_TLSAUTH_USERNAME,
                      config->tls_username);
      if(config->tls_password)
        my_setopt_str(curl, CURLOPT_TLSAUTH_PASSWORD,
                      config->tls_password);
      if(config->tls_authtype)
        my_setopt_str(curl, CURLOPT_TLSAUTH_TYPE,
                      config->tls_authtype);
    }

    /* new in 7.22.0 */
    if(config->gssapi_delegation)
      my_setopt_str(curl, CURLOPT_GSSAPI_DELEGATION,
                    config->gssapi_delegation);

    /* new in 7.25.0 */
    if(config->ssl_allow_beast)
      my_setopt(curl, CURLOPT_SSL_OPTIONS, (long)CURLSSLOPT_ALLOW_BEAST);

    if(config->mail_auth)
      my_setopt_str(curl, CURLOPT_MAIL_AUTH, config->mail_auth);

    /* initialize retry vars for loop below */
    retry_sleep_default = (config->retry_delay) ?
      config->retry_delay*1000L : RETRY_SLEEP_DEFAULT; /* ms */

    retry_numretries = config->req_retry;
    retry_sleep = retry_sleep_default; /* ms */
    retrystart = tvnow();

#ifndef CURL_DISABLE_LIBCURL_OPTION
    res = easysrc_perform();
    if(res) {
      goto show_error;
    }
#endif

    for(;;) {
      res = curl_easy_perform(curl);
      /* if retry-max-time is non-zero, make sure we haven't exceeded the
         time */
      if(retry_numretries &&
         (!config->retry_maxtime ||
          (tvdiff(tvnow(), retrystart) < config->retry_maxtime*1000)) ) {
        enum {
          RETRY_NO,
          RETRY_TIMEOUT,
          RETRY_HTTP,
          RETRY_FTP,
          RETRY_LAST /* not used */
        } retry = RETRY_NO;
        long response;
        if(CURLE_OPERATION_TIMEDOUT == res)
          /* retry timeout always */
          retry = RETRY_TIMEOUT;
        else if(CURLE_OK == res) {
          /* Check for HTTP transient errors */
          char *this_url=NULL;
          curl_easy_getinfo(curl, CURLINFO_EFFECTIVE_URL, &this_url);
          if(this_url &&
             curlx_strnequal(this_url, "http", 4)) {
            /* This was HTTP(S) */
            curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response);

            switch(response) {
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
        else if(CURLE_LOGIN_DENIED == res) {
          curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response);

          if(response/100 == 4)
            /*
             * This is typically when the FTP server only allows a certain
             * amount of users and we are not one of them.  All 4xx codes
             * are transient.
             */
            retry = RETRY_FTP;
        }

        if(retry) {
          static const char * const m[]={NULL,
                                         "timeout",
                                         "HTTP error",
                                         "FTP error"
          };
          warnf(config, "Transient problem: %s "
                "Will retry in %ld seconds. "
                "%ld retries left.\n",
                m[retry],
                retry_sleep/1000,
                retry_numretries);

          tool_go_sleep(retry_sleep);
          retry_numretries--;
          if(!config->retry_delay) {
            retry_sleep *= 2;
            if(retry_sleep > RETRY_SLEEP_MAX)
              retry_sleep = RETRY_SLEEP_MAX;
          }
          curl_truncate_file(config, outs);
          continue;
        }
      } /* if retry_numretries */
      else {
        /* Metalink: Decide to try the next resource or
           not. Basically, we want to try the next resource if
           download was not successful. */
        long response;
        if(CURLE_OPERATION_TIMEDOUT == res) {
          try_next_res = 1;
        }
        else if(CURLE_OK == res) {
          char *this_url=NULL;
          curl_easy_getinfo(curl, CURLINFO_EFFECTIVE_URL, &this_url);
          if(this_url &&
             curlx_strnequal(this_url, "http", 4)) {
            /* This was HTTP(S) */
            curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response);

            switch(response) {
            case 400:
            case 401:
            case 402:
            case 403:
            case 404:
            case 405:
            case 406:
            case 407:
            case 408:
            case 409:
            case 410:
            case 411:
            case 412:
            case 413:
            case 414:
            case 415:
            case 416:
            case 417:
              try_next_res = 1;
              break;
            }
          }
        }
        else if(CURLE_LOGIN_DENIED == res) {
          if(response/100 == 5)
            /*
             * For permanent negative return code, try the next resource.
             */
            try_next_res = 1;
        }
      }

      /* In all ordinary cases, just break out of loop here */
      retry_sleep = retry_sleep_default;
      break;

    }
    if(try_next_res == 1) {
      if(mlres+1) {
        warnf(config, "The remote server returned negative response. "
              "Will try to the next resource.");
      }
      curl_truncate_file(config, outs);
    }
    else
      break;
  }
  if((config->progressmode == CURL_PROGRESS_BAR) &&
     progressbar.calls) {
    /* if the custom progress bar has been displayed, we output a
       newline here */
    fputs("\n", progressbar.out);
  }

  if(config->writeout) {
    ourWriteOut(curl, &outs, config->writeout);
  }
#ifdef USE_ENVIRONMENT
  if(config->writeenv)
    ourWriteEnv(curl);
#endif

show_error:

#ifdef  VMS
  if(!config->showerror)  {
    vms_show = VMSSTS_HIDE;
  }
#else
  if((res!=CURLE_OK) && config->showerror) {
    fprintf(config->errors, "curl: (%d) %s\n", res,
            errorbuffer[0]? errorbuffer:
            curl_easy_strerror((CURLcode)res));
    if(CURLE_SSL_CACERT == res) {
#define CURL_CA_CERT_ERRORMSG1                                  \
"More details here: http://curl.haxx.se/docs/sslcerts.html\n\n" \
"curl performs SSL certificate verification by default, using a \"bundle\"\n" \
" of Certificate Authority (CA) public keys (CA certs). If the default\n" \
" bundle file isn't adequate, you can specify an alternate file\n" \
" using the --cacert option.\n"

#define CURL_CA_CERT_ERRORMSG2 \
"If this HTTPS server uses a certificate signed by a CA represented in\n" \
" the bundle, the certificate verification probably failed due to a\n" \
" problem with the certificate (it might be expired, or the name might\n" \
" not match the domain name in the URL).\n" \
"If you'd like to turn off curl's verification of the certificate, use\n" \
" the -k (or --insecure) option.\n"

      fprintf(config->errors, "%s%s",
              CURL_CA_CERT_ERRORMSG1,
              CURL_CA_CERT_ERRORMSG2 );
    }
  }
#endif

  if(outfile && !curlx_strequal(outfile, "-") && outs.stream)
    fclose(outs.stream);

#ifdef HAVE_UTIME
  /* Important that we set the time _after_ the file has been
     closed, as is done above here */
  if(config->remote_time && outs.filename) {
    /* ask libcurl if we got a time. Pretty please */
    long filetime;
    curl_easy_getinfo(curl, CURLINFO_FILETIME, &filetime);
    if(filetime >= 0) {
      struct utimbuf times;
      times.actime = (time_t)filetime;
      times.modtime = (time_t)filetime;
      utime(outs.filename, &times); /* set the time we got */
    }
  }
#endif
#ifdef __AMIGA__
  /* Set the url as comment for the file. (up to 80 chars are allowed)
   */
  if(strlen(url) > 78)
    url[79] = '\0';

  SetComment( outs.filename, url);
#endif

  if(filename)
    free(filename);
  if(outfile)
    free(outfile);

  if(infdopen)
    close(infd);
  if(outfiles)
    free(outfiles);

  return 0;
}

void clean_metalink(struct Configurable *config)
{
  while(config->metalinkfile_list) {
    struct metalinkfile *mlfile = config->metalinkfile_list;
    config->metalinkfile_list = config->metalinkfile_list->next;
    free(mlfile);
  }
  config->metalinkfile_last = 0;
  while(config->metalink_list) {
    struct metalink *ml = config->metalink_list;
    config->metalink_list = config->metalink_list->next;
    metalink_delete(ml->metalink);
    free(ml);
  }
  config->metalink_last = 0;
}
