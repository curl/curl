/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2014, Daniel Stenberg, <daniel@haxx.se>, et al.
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

#ifdef HAVE_FCNTL_H
#  include <fcntl.h>
#endif

#ifdef HAVE_UTIME_H
#  include <utime.h>
#elif defined(HAVE_SYS_UTIME_H)
#  include <sys/utime.h>
#endif

#ifdef HAVE_LOCALE_H
#  include <locale.h>
#endif

#ifdef HAVE_NETINET_TCP_H
#  include <netinet/tcp.h>
#endif

#ifdef __VMS
#  include <fabdef.h>
#endif

#include "rawstr.h"

#define ENABLE_CURLX_PRINTF
/* use our own printf() functions */
#include "curlx.h"

#include "tool_binmode.h"
#include "tool_cfgable.h"
#include "tool_cb_dbg.h"
#include "tool_cb_hdr.h"
#include "tool_cb_prg.h"
#include "tool_cb_rea.h"
#include "tool_cb_see.h"
#include "tool_cb_wrt.h"
#include "tool_dirhie.h"
#include "tool_doswin.h"
#include "tool_easysrc.h"
#include "tool_getparam.h"
#include "tool_helpers.h"
#include "tool_homedir.h"
#include "tool_libinfo.h"
#include "tool_main.h"
#include "tool_metalink.h"
#include "tool_msgs.h"
#include "tool_operate.h"
#include "tool_operhlp.h"
#include "tool_paramhlp.h"
#include "tool_parsecfg.h"
#include "tool_setopt.h"
#include "tool_sleep.h"
#include "tool_urlglob.h"
#include "tool_util.h"
#include "tool_writeenv.h"
#include "tool_writeout.h"
#include "tool_xattr.h"
#include "tool_vms.h"
#include "tool_help.h"
#include "tool_hugehelp.h"

#include "memdebug.h" /* keep this as LAST include */

#ifdef CURLDEBUG
/* libcurl's debug builds provide an extra function */
CURLcode curl_easy_perform_ev(CURL *easy);
#endif

#define CURLseparator  "--_curl_--"

#ifndef O_BINARY
/* since O_BINARY as used in bitmasks, setting it to zero makes it usable in
   source code but yet it doesn't ruin anything */
#  define O_BINARY 0
#endif

#define CURL_CA_CERT_ERRORMSG1                                              \
  "More details here: http://curl.haxx.se/docs/sslcerts.html\n\n"           \
  "curl performs SSL certificate verification by default, "                 \
  "using a \"bundle\"\n"                                                    \
  " of Certificate Authority (CA) public keys (CA certs). If the default\n" \
  " bundle file isn't adequate, you can specify an alternate file\n"        \
  " using the --cacert option.\n"

#define CURL_CA_CERT_ERRORMSG2                                              \
  "If this HTTPS server uses a certificate signed by a CA represented in\n" \
  " the bundle, the certificate verification probably failed due to a\n"    \
  " problem with the certificate (it might be expired, or the name might\n" \
  " not match the domain name in the URL).\n"                               \
  "If you'd like to turn off curl's verification of the certificate, use\n" \
  " the -k (or --insecure) option.\n"

static bool is_fatal_error(CURLcode code)
{
  switch(code) {
  /* TODO: Should CURLE_SSL_CACERT be included as critical error ? */
  case CURLE_FAILED_INIT:
  case CURLE_OUT_OF_MEMORY:
  case CURLE_UNKNOWN_OPTION:
  case CURLE_FUNCTION_NOT_FOUND:
  case CURLE_BAD_FUNCTION_ARGUMENT:
    /* critical error */
    return TRUE;
  default:
    break;
  }

  /* no error or not critical */
  return FALSE;
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
static curl_off_t vms_realfilesize(const char * name,
                                   const struct_stat * stat_buf)
{
  char buffer[8192];
  curl_off_t count;
  int ret_stat;
  FILE * file;

  file = fopen(name, "r");
  if(file == NULL) {
    return 0;
  }
  count = 0;
  ret_stat = 1;
  while(ret_stat > 0) {
    ret_stat = fread(buffer, 1, sizeof(buffer), file);
    if(ret_stat != 0)
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
static curl_off_t VmsSpecialSize(const char * name,
                                 const struct_stat * stat_buf)
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

static CURLcode operate_do(struct GlobalConfig *global,
                           struct OperationConfig *config)
{
  char errorbuffer[CURL_ERROR_SIZE];
  struct ProgressData progressbar;
  struct getout *urlnode;

  struct HdrCbData hdrcbdata;
  struct OutStruct heads;

  metalinkfile *mlfile_last = NULL;

  CURL *curl = config->easy;
  char *httpgetfields = NULL;

  int res = 0;
  unsigned long li;

  /* Save the values of noprogress and isatty to restore them later on */
  bool orig_noprogress = global->noprogress;
  bool orig_isatty = global->isatty;

  errorbuffer[0] = '\0';

  /* default headers output stream is stdout */
  memset(&hdrcbdata, 0, sizeof(struct HdrCbData));
  memset(&heads, 0, sizeof(struct OutStruct));
  heads.stream = stdout;
  heads.config = config;

  /*
  ** Beyond this point no return'ing from this function allowed.
  ** Jump to label 'quit_curl' in order to abandon this function
  ** from outside of nested loops further down below.
  */

  /* Check we have a url */
  if(!config->url_list || !config->url_list->url) {
    helpf(global->errors, "no URL specified!\n");
    res = CURLE_FAILED_INIT;
    goto quit_curl;
  }

  /* On WIN32 we can't set the path to curl-ca-bundle.crt
   * at compile time. So we look here for the file in two ways:
   * 1: look at the environment variable CURL_CA_BUNDLE for a path
   * 2: if #1 isn't found, use the windows API function SearchPath()
   *    to find it along the app's path (includes app's dir and CWD)
   *
   * We support the environment variable thing for non-Windows platforms
   * too. Just for the sake of it.
   */
  if(!config->cacert &&
     !config->capath &&
     !config->insecure_ok) {
    char *env;
    env = curlx_getenv("CURL_CA_BUNDLE");
    if(env) {
      config->cacert = strdup(env);
      if(!config->cacert) {
        curl_free(env);
        helpf(global->errors, "out of memory\n");
        res = CURLE_OUT_OF_MEMORY;
        goto quit_curl;
      }
    }
    else {
      env = curlx_getenv("SSL_CERT_DIR");
      if(env) {
        config->capath = strdup(env);
        if(!config->capath) {
          curl_free(env);
          helpf(global->errors, "out of memory\n");
          res = CURLE_OUT_OF_MEMORY;
          goto quit_curl;
        }
      }
      else {
        env = curlx_getenv("SSL_CERT_FILE");
        if(env) {
          config->cacert = strdup(env);
          if(!config->cacert) {
            curl_free(env);
            helpf(global->errors, "out of memory\n");
            res = CURLE_OUT_OF_MEMORY;
            goto quit_curl;
          }
        }
      }
    }

    if(env)
      curl_free(env);
#ifdef WIN32
    else {
      res = FindWin32CACert(config, "curl-ca-bundle.crt");
      if(res)
        goto quit_curl;
    }
#endif
  }

  if(config->postfields) {
    if(config->use_httpget) {
      /* Use the postfields data for a http get */
      httpgetfields = strdup(config->postfields);
      Curl_safefree(config->postfields);
      if(!httpgetfields) {
        helpf(global->errors, "out of memory\n");
        res = CURLE_OUT_OF_MEMORY;
        goto quit_curl;
      }
      if(SetHTTPrequest(config,
                        (config->no_body?HTTPREQ_HEAD:HTTPREQ_GET),
                        &config->httpreq)) {
        res = CURLE_FAILED_INIT;
        goto quit_curl;
      }
    }
    else {
      if(SetHTTPrequest(config, HTTPREQ_SIMPLEPOST, &config->httpreq)) {
        res = CURLE_FAILED_INIT;
        goto quit_curl;
      }
    }
  }

  /* Single header file for all URLs */
  if(config->headerfile) {
    /* open file for output: */
    if(!curlx_strequal(config->headerfile, "-")) {
      FILE *newfile = fopen(config->headerfile, "wb");
      if(!newfile) {
        warnf(config, "Failed to open %s\n", config->headerfile);
        res = CURLE_WRITE_ERROR;
        goto quit_curl;
      }
      else {
        heads.filename = config->headerfile;
        heads.s_isreg = TRUE;
        heads.fopened = TRUE;
        heads.stream = newfile;
      }
    }
    else {
      /* always use binary mode for protocol header output */
      set_binmode(heads.stream);
    }
  }

  /*
  ** Nested loops start here.
  */

  /* loop through the list of given URLs */

  for(urlnode = config->url_list; urlnode; urlnode = urlnode->next) {

    unsigned long up; /* upload file counter within a single upload glob */
    char *infiles; /* might be a glob pattern */
    char *outfiles;
    unsigned long infilenum;
    URLGlob *inglob;

    int metalink = 0; /* nonzero for metalink download. */
    metalinkfile *mlfile;
    metalink_resource *mlres;

    outfiles = NULL;
    infilenum = 1;
    inglob = NULL;

    if(urlnode->flags & GETOUT_METALINK) {
      metalink = 1;
      if(mlfile_last == NULL) {
        mlfile_last = config->metalinkfile_list;
      }
      mlfile = mlfile_last;
      mlfile_last = mlfile_last->next;
      mlres = mlfile->resource;
    }
    else {
      mlfile = NULL;
      mlres = NULL;
    }

    /* urlnode->url is the full URL (it might be NULL) */

    if(!urlnode->url) {
      /* This node has no URL. Free node data without destroying the
         node itself nor modifying next pointer and continue to next */
      Curl_safefree(urlnode->outfile);
      Curl_safefree(urlnode->infile);
      urlnode->flags = 0;
      continue; /* next URL please */
    }

    /* save outfile pattern before expansion */
    if(urlnode->outfile) {
      outfiles = strdup(urlnode->outfile);
      if(!outfiles) {
        helpf(global->errors, "out of memory\n");
        res = CURLE_OUT_OF_MEMORY;
        break;
      }
    }

    infiles = urlnode->infile;

    if(!config->globoff && infiles) {
      /* Unless explicitly shut off */
      res = glob_url(&inglob, infiles, &infilenum,
                     global->showerror?global->errors:NULL);
      if(res) {
        Curl_safefree(outfiles);
        break;
      }
    }

    /* Here's the loop for uploading multiple files within the same
       single globbed string. If no upload, we enter the loop once anyway. */
    for(up = 0 ; up < infilenum; up++) {

      char *uploadfile; /* a single file, never a glob */
      int separator;
      URLGlob *urls;
      unsigned long urlnum;

      uploadfile = NULL;
      urls = NULL;
      urlnum = 0;

      if(!up && !infiles)
        Curl_nop_stmt;
      else {
        if(inglob) {
          res = glob_next_url(&uploadfile, inglob);
          if(res == CURLE_OUT_OF_MEMORY)
            helpf(global->errors, "out of memory\n");
        }
        else if(!up) {
          uploadfile = strdup(infiles);
          if(!uploadfile) {
            helpf(global->errors, "out of memory\n");
            res = CURLE_OUT_OF_MEMORY;
          }
        }
        else
          uploadfile = NULL;
        if(!uploadfile)
          break;
      }

      if(metalink) {
        /* For Metalink download, we don't use glob. Instead we use
           the number of resources as urlnum. */
        urlnum = count_next_metalink_resource(mlfile);
      }
      else
      if(!config->globoff) {
        /* Unless explicitly shut off, we expand '{...}' and '[...]'
           expressions and return total number of URLs in pattern set */
        res = glob_url(&urls, urlnode->url, &urlnum,
                       global->showerror?global->errors:NULL);
        if(res) {
          Curl_safefree(uploadfile);
          break;
        }
      }
      else
        urlnum = 1; /* without globbing, this is a single URL */

      /* if multiple files extracted to stdout, insert separators! */
      separator= ((!outfiles || curlx_strequal(outfiles, "-")) && urlnum > 1);

      /* Here's looping around each globbed URL */
      for(li = 0 ; li < urlnum; li++) {

        int infd;
        bool infdopen;
        char *outfile;
        struct OutStruct outs;
        struct InStruct input;
        struct timeval retrystart;
        curl_off_t uploadfilesize;
        long retry_numretries;
        long retry_sleep_default;
        long retry_sleep;
        char *this_url = NULL;
        int metalink_next_res = 0;

        outfile = NULL;
        infdopen = FALSE;
        infd = STDIN_FILENO;
        uploadfilesize = -1; /* -1 means unknown */

        /* default output stream is stdout */
        memset(&outs, 0, sizeof(struct OutStruct));
        outs.stream = stdout;
        outs.config = config;

        if(metalink) {
          /* For Metalink download, use name in Metalink file as
             filename. */
          outfile = strdup(mlfile->filename);
          if(!outfile) {
            res = CURLE_OUT_OF_MEMORY;
            goto show_error;
          }
          this_url = strdup(mlres->url);
          if(!this_url) {
            res = CURLE_OUT_OF_MEMORY;
            goto show_error;
          }
        }
        else {
          if(urls) {
            res = glob_next_url(&this_url, urls);
            if(res)
              goto show_error;
          }
          else if(!li) {
            this_url = strdup(urlnode->url);
            if(!this_url) {
              res = CURLE_OUT_OF_MEMORY;
              goto show_error;
            }
          }
          else
            this_url = NULL;
          if(!this_url)
            break;

          if(outfiles) {
            outfile = strdup(outfiles);
            if(!outfile) {
              res = CURLE_OUT_OF_MEMORY;
              goto show_error;
            }
          }
        }

        if(((urlnode->flags&GETOUT_USEREMOTE) ||
            (outfile && !curlx_strequal("-", outfile))) &&
           (metalink || !config->use_metalink)) {

          /*
           * We have specified a file name to store the result in, or we have
           * decided we want to use the remote file name.
           */

          if(!outfile) {
            /* extract the file name from the URL */
            res = get_url_file_name(&outfile, this_url);
            if(res)
              goto show_error;
            if((!outfile || !*outfile) && !config->content_disposition) {
              helpf(global->errors, "Remote file name has no length!\n");
              res = CURLE_WRITE_ERROR;
              goto quit_urls;
            }
#if defined(MSDOS) || defined(WIN32)
            /* For DOS and WIN32, we do some major replacing of
               bad characters in the file name before using it */
            outfile = sanitize_dos_name(outfile);
            if(!outfile) {
              res = CURLE_OUT_OF_MEMORY;
              goto show_error;
            }
#endif /* MSDOS || WIN32 */
          }
          else if(urls) {
            /* fill '#1' ... '#9' terms from URL pattern */
            char *storefile = outfile;
            res = glob_match_url(&outfile, storefile, urls);
            Curl_safefree(storefile);
            if(res) {
              /* bad globbing */
              warnf(config, "bad output glob!\n");
              goto quit_urls;
            }
          }

          /* Create the directory hierarchy, if not pre-existent to a multiple
             file output call */

          if(config->create_dirs || metalink) {
            res = create_dir_hierarchy(outfile, global->errors);
            /* create_dir_hierarchy shows error upon CURLE_WRITE_ERROR */
            if(res == CURLE_WRITE_ERROR)
              goto quit_urls;
            if(res) {
              goto show_error;
            }
          }

          if((urlnode->flags & GETOUT_USEREMOTE)
             && config->content_disposition) {
            /* Our header callback MIGHT set the filename */
            DEBUGASSERT(!outs.filename);
          }

          if(config->resume_from_current) {
            /* We're told to continue from where we are now. Get the size
               of the file as it is now and open it for append instead */
            struct_stat fileinfo;
            /* VMS -- Danger, the filesize is only valid for stream files */
            if(0 == stat(outfile, &fileinfo))
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
            FILE *file = fopen(outfile, config->resume_from?"ab":"wb",
                               "ctx=stm", "rfm=stmlf", "rat=cr", "mrs=0");
#else
            /* open file for output: */
            FILE *file = fopen(outfile, config->resume_from?"ab":"wb");
#endif
            if(!file) {
              helpf(global->errors, "Can't open '%s'!\n", outfile);
              res = CURLE_WRITE_ERROR;
              goto quit_urls;
            }
            outs.fopened = TRUE;
            outs.stream = file;
            outs.init = config->resume_from;
          }
          else {
            outs.stream = NULL; /* open when needed */
          }
          outs.filename = outfile;
          outs.s_isreg = TRUE;
        }

        if(uploadfile && !stdin_upload(uploadfile)) {
          /*
           * We have specified a file to upload and it isn't "-".
           */
          struct_stat fileinfo;

          this_url = add_file_name_to_url(curl, this_url, uploadfile);
          if(!this_url) {
            res = CURLE_OUT_OF_MEMORY;
            goto show_error;
          }
          /* VMS Note:
           *
           * Reading binary from files can be a problem...  Only FIXED, VAR
           * etc WITHOUT implied CC will work Others need a \n appended to a
           * line
           *
           * - Stat gives a size but this is UNRELIABLE in VMS As a f.e. a
           * fixed file with implied CC needs to have a byte added for every
           * record processed, this can by derived from Filesize & recordsize
           * for VARiable record files the records need to be counted!  for
           * every record add 1 for linefeed and subtract 2 for the record
           * header for VARIABLE header files only the bare record data needs
           * to be considered with one appended if implied CC
           */
#ifdef __VMS
          /* Calculate the real upload site for VMS */
          infd = -1;
          if(stat(uploadfile, &fileinfo) == 0) {
            fileinfo.st_size = VmsSpecialSize(uploadfile, &fileinfo);
            switch (fileinfo.st_fab_rfm) {
            case FAB$C_VAR:
            case FAB$C_VFC:
            case FAB$C_STMCR:
              infd = open(uploadfile, O_RDONLY | O_BINARY);
              break;
            default:
              infd = open(uploadfile, O_RDONLY | O_BINARY,
                          "rfm=stmlf", "ctx=stm");
            }
          }
          if(infd == -1)
#else
          infd = open(uploadfile, O_RDONLY | O_BINARY);
          if((infd == -1) || fstat(infd, &fileinfo))
#endif
          {
            helpf(global->errors, "Can't open '%s'!\n", uploadfile);
            if(infd != -1) {
              close(infd);
              infd = STDIN_FILENO;
            }
            res = CURLE_READ_ERROR;
            goto quit_urls;
          }
          infdopen = TRUE;

          /* we ignore file size for char/block devices, sockets, etc. */
          if(S_ISREG(fileinfo.st_mode))
            uploadfilesize = fileinfo.st_size;

        }
        else if(uploadfile && stdin_upload(uploadfile)) {
          /* count to see if there are more than one auth bit set
             in the authtype field */
          int authbits = 0;
          int bitcheck = 0;
          while(bitcheck < 32) {
            if(config->authtype & (1UL << bitcheck++)) {
              authbits++;
              if(authbits > 1) {
                /* more than one, we're done! */
                break;
              }
            }
          }

          /*
           * If the user has also selected --anyauth or --proxy-anyauth
           * we should warn him/her.
           */
          if(config->proxyanyauth || (authbits>1)) {
            warnf(config,
                  "Using --anyauth or --proxy-anyauth with upload from stdin"
                  " involves a big risk of it not working. Use a temporary"
                  " file or a fixed auth type instead!\n");
          }

          DEBUGASSERT(infdopen == FALSE);
          DEBUGASSERT(infd == STDIN_FILENO);

          set_binmode(stdin);
          if(curlx_strequal(uploadfile, ".")) {
            if(curlx_nonblock((curl_socket_t)infd, TRUE) < 0)
              warnf(config,
                    "fcntl failed on fd=%d: %s\n", infd, strerror(errno));
          }
        }

        if(uploadfile && config->resume_from_current)
          config->resume_from = -1; /* -1 will then force get-it-yourself */

        if(output_expected(this_url, uploadfile) && outs.stream &&
           isatty(fileno(outs.stream)))
          /* we send the output to a tty, therefore we switch off the progress
             meter */
          global->noprogress = global->isatty = TRUE;
        else {
          /* progress meter is per download, so restore config
             values */
          global->noprogress = orig_noprogress;
          global->isatty = orig_isatty;
        }

        if(urlnum > 1 && !global->mute) {
          fprintf(global->errors, "\n[%lu/%lu]: %s --> %s\n",
                  li+1, urlnum, this_url, outfile ? outfile : "<stdout>");
          if(separator)
            printf("%s%s\n", CURLseparator, this_url);
        }
        if(httpgetfields) {
          char *urlbuffer;
          /* Find out whether the url contains a file name */
          const char *pc = strstr(this_url, "://");
          char sep = '?';
          if(pc)
            pc += 3;
          else
            pc = this_url;

          pc = strrchr(pc, '/'); /* check for a slash */

          if(pc) {
            /* there is a slash present in the URL */

            if(strchr(pc, '?'))
              /* Ouch, there's already a question mark in the URL string, we
                 then append the data with an ampersand separator instead! */
              sep='&';
          }
          /*
           * Then append ? followed by the get fields to the url.
           */
          if(pc)
            urlbuffer = aprintf("%s%c%s", this_url, sep, httpgetfields);
          else
            /* Append  / before the ? to create a well-formed url
               if the url contains a hostname only
            */
            urlbuffer = aprintf("%s/?%s", this_url, httpgetfields);

          if(!urlbuffer) {
            res = CURLE_OUT_OF_MEMORY;
            goto show_error;
          }

          Curl_safefree(this_url); /* free previous URL */
          this_url = urlbuffer; /* use our new URL instead! */
        }

        if(!global->errors)
          global->errors = stderr;

        if((!outfile || !strcmp(outfile, "-")) && !config->use_ascii) {
          /* We get the output to stdout and we have not got the ASCII/text
             flag, then set stdout to be binary */
          set_binmode(stdout);
        }

        if(config->tcp_nodelay)
          my_setopt(curl, CURLOPT_TCP_NODELAY, 1L);

        /* where to store */
        my_setopt(curl, CURLOPT_WRITEDATA, &outs);
        if(metalink || !config->use_metalink)
          /* what call to write */
          my_setopt(curl, CURLOPT_WRITEFUNCTION, tool_write_cb);
#ifdef USE_METALINK
        else
          /* Set Metalink specific write callback function to parse
             XML data progressively. */
          my_setopt(curl, CURLOPT_WRITEFUNCTION, metalink_write_cb);
#endif /* USE_METALINK */

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
          my_setopt(curl, CURLOPT_BUFFERSIZE, (long)config->recvpersecond);

        /* size of uploaded file: */
        if(uploadfilesize != -1)
          my_setopt(curl, CURLOPT_INFILESIZE_LARGE, uploadfilesize);
        my_setopt_str(curl, CURLOPT_URL, this_url);     /* what to fetch */
        my_setopt(curl, CURLOPT_NOPROGRESS, global->noprogress?1L:0L);
        if(config->no_body) {
          my_setopt(curl, CURLOPT_NOBODY, 1L);
          my_setopt(curl, CURLOPT_HEADER, 1L);
        }
        /* If --metalink is used, we ignore --include (headers in
           output) option because mixing headers to the body will
           confuse XML parser and/or hash check will fail. */
        else if(!config->use_metalink)
          my_setopt(curl, CURLOPT_HEADER, config->include_headers?1L:0L);

        if(config->xoauth2_bearer)
          my_setopt_str(curl, CURLOPT_XOAUTH2_BEARER, config->xoauth2_bearer);

#if !defined(CURL_DISABLE_PROXY)
        {
          /* TODO: Make this a run-time check instead of compile-time one. */

          my_setopt_str(curl, CURLOPT_PROXY, config->proxy);
          my_setopt_str(curl, CURLOPT_PROXYUSERPWD, config->proxyuserpwd);

          /* new in libcurl 7.3 */
          my_setopt(curl, CURLOPT_HTTPPROXYTUNNEL, config->proxytunnel?1L:0L);

          /* new in libcurl 7.5 */
          if(config->proxy)
            my_setopt_enum(curl, CURLOPT_PROXYTYPE, (long)config->proxyver);

          /* new in libcurl 7.10 */
          if(config->socksproxy) {
            my_setopt_str(curl, CURLOPT_PROXY, config->socksproxy);
            my_setopt_enum(curl, CURLOPT_PROXYTYPE, (long)config->socksver);
          }

          /* new in libcurl 7.10.6 */
          if(config->proxyanyauth)
            my_setopt_bitmask(curl, CURLOPT_PROXYAUTH,
                              (long)CURLAUTH_ANY);
          else if(config->proxynegotiate)
            my_setopt_bitmask(curl, CURLOPT_PROXYAUTH,
                              (long)CURLAUTH_GSSNEGOTIATE);
          else if(config->proxyntlm)
            my_setopt_bitmask(curl, CURLOPT_PROXYAUTH,
                              (long)CURLAUTH_NTLM);
          else if(config->proxydigest)
            my_setopt_bitmask(curl, CURLOPT_PROXYAUTH,
                              (long)CURLAUTH_DIGEST);
          else if(config->proxybasic)
            my_setopt_bitmask(curl, CURLOPT_PROXYAUTH,
                              (long)CURLAUTH_BASIC);

          /* new in libcurl 7.19.4 */
          my_setopt(curl, CURLOPT_NOPROXY, config->noproxy);
        }
#endif

        my_setopt(curl, CURLOPT_FAILONERROR, config->failonerror?1L:0L);
        my_setopt(curl, CURLOPT_UPLOAD, uploadfile?1L:0L);
        my_setopt(curl, CURLOPT_DIRLISTONLY, config->dirlistonly?1L:0L);
        my_setopt(curl, CURLOPT_APPEND, config->ftp_append?1L:0L);

        if(config->netrc_opt)
          my_setopt_enum(curl, CURLOPT_NETRC, (long)CURL_NETRC_OPTIONAL);
        else if(config->netrc || config->netrc_file)
          my_setopt_enum(curl, CURLOPT_NETRC, (long)CURL_NETRC_REQUIRED);
        else
          my_setopt_enum(curl, CURLOPT_NETRC, (long)CURL_NETRC_IGNORED);

        if(config->netrc_file)
          my_setopt(curl, CURLOPT_NETRC_FILE, config->netrc_file);

        my_setopt(curl, CURLOPT_TRANSFERTEXT, config->use_ascii?1L:0L);
        if(config->login_options)
          my_setopt_str(curl, CURLOPT_LOGIN_OPTIONS, config->login_options);
        my_setopt_str(curl, CURLOPT_USERPWD, config->userpwd);
        my_setopt_str(curl, CURLOPT_RANGE, config->range);
        my_setopt(curl, CURLOPT_ERRORBUFFER, errorbuffer);
        my_setopt(curl, CURLOPT_TIMEOUT_MS, (long)(config->timeout * 1000));

        if(built_in_protos & CURLPROTO_HTTP) {

          long postRedir = 0;

          my_setopt(curl, CURLOPT_FOLLOWLOCATION,
                    config->followlocation?1L:0L);
          my_setopt(curl, CURLOPT_UNRESTRICTED_AUTH,
                    config->unrestricted_auth?1L:0L);

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
          my_setopt(curl, CURLOPT_AUTOREFERER, config->autoreferer?1L:0L);
          my_setopt_str(curl, CURLOPT_USERAGENT, config->useragent);
          my_setopt_slist(curl, CURLOPT_HTTPHEADER, config->headers);

          /* new in libcurl 7.5 */
          my_setopt(curl, CURLOPT_MAXREDIRS, config->maxredirs);

          /* new in libcurl 7.9.1 */
          if(config->httpversion)
            my_setopt_enum(curl, CURLOPT_HTTP_VERSION, config->httpversion);

          /* new in libcurl 7.10.6 (default is Basic) */
          if(config->authtype)
            my_setopt_bitmask(curl, CURLOPT_HTTPAUTH, (long)config->authtype);

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

        } /* (built_in_protos & CURLPROTO_HTTP) */

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

        my_setopt_str(curl, CURLOPT_SSLCERT, config->cert);
        my_setopt_str(curl, CURLOPT_SSLCERTTYPE, config->cert_type);
        my_setopt_str(curl, CURLOPT_SSLKEY, config->key);
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
            my_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
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
          my_setopt(curl, CURLOPT_FILETIME, 1L);
        }

        my_setopt(curl, CURLOPT_CRLF, config->crlf?1L:0L);
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
          my_setopt(curl, CURLOPT_COOKIESESSION, config->cookiesession?1L:0L);
        }
#endif

        my_setopt_enum(curl, CURLOPT_SSLVERSION, config->ssl_version);
        my_setopt_enum(curl, CURLOPT_TIMECONDITION, (long)config->timecond);
        my_setopt(curl, CURLOPT_TIMEVALUE, (long)config->condtime);
        my_setopt_str(curl, CURLOPT_CUSTOMREQUEST, config->customrequest);
        my_setopt(curl, CURLOPT_STDERR, global->errors);

        /* three new ones in libcurl 7.3: */
        my_setopt_str(curl, CURLOPT_INTERFACE, config->iface);
        my_setopt_str(curl, CURLOPT_KRBLEVEL, config->krblevel);

        progressbarinit(&progressbar, config);
        if((global->progressmode == CURL_PROGRESS_BAR) &&
           !global->noprogress && !global->mute) {
          /* we want the alternative style, then we have to implement it
             ourselves! */
          my_setopt(curl, CURLOPT_XFERINFOFUNCTION, tool_progress_cb);
          my_setopt(curl, CURLOPT_XFERINFODATA, &progressbar);
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
        my_setopt_str(curl, CURLOPT_RANDOM_FILE, config->random_file);
        my_setopt_str(curl, CURLOPT_EGDSOCKET, config->egd_file);
        my_setopt(curl, CURLOPT_CONNECTTIMEOUT_MS,
                  (long)(config->connecttimeout * 1000));

        if(config->cipher_list)
          my_setopt_str(curl, CURLOPT_SSL_CIPHER_LIST, config->cipher_list);

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
          res = res_setopt_str(curl, CURLOPT_SSLENGINE, config->engine);
          if(res)
            goto show_error;
          my_setopt(curl, CURLOPT_SSLENGINE_DEFAULT, 1L);
        }

        /* new in curl 7.10.7, extended in 7.19.4 but this only sets 0 or 1 */
        my_setopt(curl, CURLOPT_FTP_CREATE_MISSING_DIRS,
                  config->ftp_create_dirs?1L:0L);

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

        my_setopt(curl, CURLOPT_IGNORE_CONTENT_LENGTH, config->ignorecl?1L:0L);

        /* curl 7.14.2 */
        my_setopt(curl, CURLOPT_FTP_SKIP_PASV_IP, config->ftp_skip_ip?1L:0L);

        /* curl 7.15.1 */
        my_setopt(curl, CURLOPT_FTP_FILEMETHOD, (long)config->ftp_filemethod);

        /* curl 7.15.2 */
        if(config->localport) {
          my_setopt(curl, CURLOPT_LOCALPORT, (long)config->localport);
          my_setopt_str(curl, CURLOPT_LOCALPORTRANGE,
                        (long)config->localportrange);
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
          my_setopt(curl, CURLOPT_FTP_USE_PRET, 1L);

        if(config->proto_present)
          my_setopt_flags(curl, CURLOPT_PROTOCOLS, config->proto);
        if(config->proto_redir_present)
          my_setopt_flags(curl, CURLOPT_REDIR_PROTOCOLS, config->proto_redir);

        if(config->content_disposition
           && (urlnode->flags & GETOUT_USEREMOTE)
           && (checkprefix("http://", this_url) ||
               checkprefix("https://", this_url)))
          hdrcbdata.honor_cd_filename = TRUE;
        else
          hdrcbdata.honor_cd_filename = FALSE;

        hdrcbdata.outs = &outs;
        hdrcbdata.heads = &heads;

        my_setopt(curl, CURLOPT_HEADERFUNCTION, tool_header_cb);
        my_setopt(curl, CURLOPT_HEADERDATA, &hdrcbdata);

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

        /* new in 7.31.0 */
        if(config->sasl_ir)
          my_setopt(curl, CURLOPT_SASL_IR, 1L);

        if(config->nonpn) {
          my_setopt(curl, CURLOPT_SSL_ENABLE_NPN, 0L);
        }

        if(config->noalpn) {
          my_setopt(curl, CURLOPT_SSL_ENABLE_ALPN, 0L);
        }

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
#ifdef USE_METALINK
          if(!metalink && config->use_metalink) {
            /* If outs.metalink_parser is non-NULL, delete it first. */
            if(outs.metalink_parser)
              metalink_parser_context_delete(outs.metalink_parser);
            outs.metalink_parser = metalink_parser_context_new();
            if(outs.metalink_parser == NULL) {
              res = CURLE_OUT_OF_MEMORY;
              goto show_error;
            }
            fprintf(config->global->errors,
                    "Metalink: parsing (%s) metalink/XML...\n", this_url);
          }
          else if(metalink)
            fprintf(config->global->errors,
                    "Metalink: fetching (%s) from (%s)...\n",
                    mlfile->filename, this_url);
#endif /* USE_METALINK */

#ifdef CURLDEBUG
          if(config->test_event_based)
            res = curl_easy_perform_ev(curl);
          else
#endif
          res = curl_easy_perform(curl);

          if(outs.is_cd_filename && outs.stream && !global->mute &&
             outs.filename)
            printf("curl: Saved to filename '%s'\n", outs.filename);

          /* if retry-max-time is non-zero, make sure we haven't exceeded the
             time */
          if(retry_numretries &&
             (!config->retry_maxtime ||
              (tvdiff(tvnow(), retrystart) <
               config->retry_maxtime*1000L)) ) {
            enum {
              RETRY_NO,
              RETRY_TIMEOUT,
              RETRY_HTTP,
              RETRY_FTP,
              RETRY_LAST /* not used */
            } retry = RETRY_NO;
            long response;
            if((CURLE_OPERATION_TIMEDOUT == res) ||
               (CURLE_COULDNT_RESOLVE_HOST == res) ||
               (CURLE_COULDNT_RESOLVE_PROXY == res) ||
               (CURLE_FTP_ACCEPT_TIMEOUT == res))
              /* retry timeout always */
              retry = RETRY_TIMEOUT;
            else if((CURLE_OK == res) ||
                    (config->failonerror &&
                     (CURLE_HTTP_RETURNED_ERROR == res))) {
              /* If it returned OK. _or_ failonerror was enabled and it
                 returned due to such an error, check for HTTP transient
                 errors to retry on. */
              char *effective_url = NULL;
              curl_easy_getinfo(curl, CURLINFO_EFFECTIVE_URL, &effective_url);
              if(effective_url &&
                 checkprefix("http", effective_url)) {
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
            else if(res) {
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
              static const char * const m[]={
                NULL, "timeout", "HTTP error", "FTP error"
              };
              warnf(config, "Transient problem: %s "
                    "Will retry in %ld seconds. "
                    "%ld retries left.\n",
                    m[retry], retry_sleep/1000L, retry_numretries);

              tool_go_sleep(retry_sleep);
              retry_numretries--;
              if(!config->retry_delay) {
                retry_sleep *= 2;
                if(retry_sleep > RETRY_SLEEP_MAX)
                  retry_sleep = RETRY_SLEEP_MAX;
              }
              if(outs.bytes && outs.filename) {
                /* We have written data to a output file, we truncate file
                 */
                if(!global->mute)
                  fprintf(global->errors, "Throwing away %"
                          CURL_FORMAT_CURL_OFF_T " bytes\n",
                          outs.bytes);
                fflush(outs.stream);
                /* truncate file at the position where we started appending */
#ifdef HAVE_FTRUNCATE
                if(ftruncate( fileno(outs.stream), outs.init)) {
                  /* when truncate fails, we can't just append as then we'll
                     create something strange, bail out */
                  if(!global->mute)
                    fprintf(global->errors,
                            "failed to truncate, exiting\n");
                  res = CURLE_WRITE_ERROR;
                  goto quit_urls;
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
              continue; /* curl_easy_perform loop */
            }
          } /* if retry_numretries */
          else if(metalink) {
            /* Metalink: Decide to try the next resource or
               not. Basically, we want to try the next resource if
               download was not successful. */
            long response;
            if(CURLE_OK == res) {
              /* TODO We want to try next resource when download was
                 not successful. How to know that? */
              char *effective_url = NULL;
              curl_easy_getinfo(curl, CURLINFO_EFFECTIVE_URL, &effective_url);
              if(effective_url &&
                 curlx_strnequal(effective_url, "http", 4)) {
                /* This was HTTP(S) */
                curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response);
                if(response != 200 && response != 206) {
                  metalink_next_res = 1;
                  fprintf(global->errors,
                          "Metalink: fetching (%s) from (%s) FAILED "
                          "(HTTP status code %d)\n",
                          mlfile->filename, this_url, response);
                }
              }
            }
            else {
              metalink_next_res = 1;
              fprintf(global->errors,
                      "Metalink: fetching (%s) from (%s) FAILED (%s)\n",
                      mlfile->filename, this_url,
                      (errorbuffer[0]) ?
                      errorbuffer : curl_easy_strerror((CURLcode)res));
            }
          }
          if(metalink && !metalink_next_res)
            fprintf(global->errors, "Metalink: fetching (%s) from (%s) OK\n",
                    mlfile->filename, this_url);

          /* In all ordinary cases, just break out of loop here */
          break; /* curl_easy_perform loop */

        }

        if((global->progressmode == CURL_PROGRESS_BAR) &&
           progressbar.calls)
          /* if the custom progress bar has been displayed, we output a
             newline here */
          fputs("\n", progressbar.out);

        if(config->writeout)
          ourWriteOut(curl, &outs, config->writeout);

        if(config->writeenv)
          ourWriteEnv(curl);

        /*
        ** Code within this loop may jump directly here to label 'show_error'
        ** in order to display an error message for CURLcode stored in 'res'
        ** variable and exit loop once that necessary writing and cleanup
        ** in label 'quit_urls' has been done.
        */

        show_error:

#ifdef __VMS
        if(is_vms_shell()) {
          /* VMS DCL shell behavior */
          if(!global->showerror)
            vms_show = VMSSTS_HIDE;
        }
        else
#endif
        if(res && global->showerror) {
          fprintf(global->errors, "curl: (%d) %s\n", res, (errorbuffer[0]) ?
                  errorbuffer : curl_easy_strerror((CURLcode)res));
          if(res == CURLE_SSL_CACERT)
            fprintf(global->errors, "%s%s",
                    CURL_CA_CERT_ERRORMSG1, CURL_CA_CERT_ERRORMSG2);
        }

        /* Fall through comment to 'quit_urls' label */

        /*
        ** Upon error condition and always that a message has already been
        ** displayed, code within this loop may jump directly here to label
        ** 'quit_urls' otherwise it should jump to 'show_error' label above.
        **
        ** When 'res' variable is _not_ CURLE_OK loop will exit once that
        ** all code following 'quit_urls' has been executed. Otherwise it
        ** will loop to the beginning from where it may exit if there are
        ** no more urls left.
        */

        quit_urls:

        /* Set file extended attributes */
        if(!res && config->xattr && outs.fopened && outs.stream) {
          int rc = fwrite_xattr(curl, fileno(outs.stream));
          if(rc)
            warnf(config, "Error setting extended attributes: %s\n",
                  strerror(errno));
        }

        /* Close the file */
        if(outs.fopened && outs.stream) {
          int rc = fclose(outs.stream);
          if(!res && rc) {
            /* something went wrong in the writing process */
            res = CURLE_WRITE_ERROR;
            fprintf(global->errors, "(%d) Failed writing body\n", res);
          }
        }
        else if(!outs.s_isreg && outs.stream) {
          /* Dump standard stream buffered data */
          int rc = fflush(outs.stream);
          if(!res && rc) {
            /* something went wrong in the writing process */
            res = CURLE_WRITE_ERROR;
            fprintf(global->errors, "(%d) Failed writing body\n", res);
          }
        }

#ifdef __AMIGA__
        if(!res && outs.s_isreg && outs.filename) {
          /* Set the url (up to 80 chars) as comment for the file */
          if(strlen(url) > 78)
            url[79] = '\0';
          SetComment(outs.filename, url);
        }
#endif

#ifdef HAVE_UTIME
        /* File time can only be set _after_ the file has been closed */
        if(!res && config->remote_time && outs.s_isreg && outs.filename) {
          /* Ask libcurl if we got a remote file time */
          long filetime = -1;
          curl_easy_getinfo(curl, CURLINFO_FILETIME, &filetime);
          if(filetime >= 0) {
            struct utimbuf times;
            times.actime = (time_t)filetime;
            times.modtime = (time_t)filetime;
            utime(outs.filename, &times); /* set the time we got */
          }
        }
#endif

#ifdef USE_METALINK
        if(!metalink && config->use_metalink && res == CURLE_OK) {
          int rv = parse_metalink(config, &outs, this_url);
          if(rv == 0)
            fprintf(config->global->errors, "Metalink: parsing (%s) OK\n",
                    this_url);
          else if(rv == -1)
            fprintf(config->global->errors, "Metalink: parsing (%s) FAILED\n",
                    this_url);
        }
        else if(metalink && res == CURLE_OK && !metalink_next_res) {
          int rv = metalink_check_hash(global, mlfile, outs.filename);
          if(rv == 0) {
            metalink_next_res = 1;
          }
        }
#endif /* USE_METALINK */

        /* No more business with this output struct */
        if(outs.alloc_filename)
          Curl_safefree(outs.filename);
#ifdef USE_METALINK
        if(outs.metalink_parser)
          metalink_parser_context_delete(outs.metalink_parser);
#endif /* USE_METALINK */
        memset(&outs, 0, sizeof(struct OutStruct));
        hdrcbdata.outs = NULL;

        /* Free loop-local allocated memory and close loop-local opened fd */

        Curl_safefree(outfile);
        Curl_safefree(this_url);

        if(infdopen)
          close(infd);

        if(metalink) {
          /* Should exit if error is fatal. */
          if(is_fatal_error(res)) {
            break;
          }
          if(!metalink_next_res)
            break;
          mlres = mlres->next;
          if(mlres == NULL)
            /* TODO If metalink_next_res is 1 and mlres is NULL,
             * set res to error code
             */
            break;
        }
        else
        if(urlnum > 1) {
          /* when url globbing, exit loop upon critical error */
          if(is_fatal_error(res))
            break;
        }
        else if(res)
          /* when not url globbing, exit loop upon any error */
          break;

      } /* loop to the next URL */

      /* Free loop-local allocated memory */

      Curl_safefree(uploadfile);

      if(urls) {
        /* Free list of remaining URLs */
        glob_cleanup(urls);
        urls = NULL;
      }

      if(infilenum > 1) {
        /* when file globbing, exit loop upon critical error */
        if(is_fatal_error(res))
          break;
      }
      else if(res)
        /* when not file globbing, exit loop upon any error */
        break;

    } /* loop to the next globbed upload file */

    /* Free loop-local allocated memory */

    Curl_safefree(outfiles);

    if(inglob) {
      /* Free list of globbed upload files */
      glob_cleanup(inglob);
      inglob = NULL;
    }

    /* Free this URL node data without destroying the
       the node itself nor modifying next pointer. */
    Curl_safefree(urlnode->url);
    Curl_safefree(urlnode->outfile);
    Curl_safefree(urlnode->infile);
    urlnode->flags = 0;

    /*
    ** Bail out upon critical errors
    */
    if(is_fatal_error(res))
      goto quit_curl;

  } /* for-loop through all URLs */

  /*
  ** Nested loops end here.
  */

  quit_curl:

  /* Reset the global config variables */
  global->noprogress = orig_noprogress;
  global->isatty = orig_isatty;

  /* Free function-local referenced allocated memory */
  Curl_safefree(httpgetfields);

  /* Free list of given URLs */
  clean_getout(config);

  hdrcbdata.heads = NULL;

  /* Close function-local opened file descriptors */
  if(heads.fopened && heads.stream)
    fclose(heads.stream);

  if(heads.alloc_filename)
    Curl_safefree(heads.filename);

  /* Release metalink related resources here */
  clean_metalink(config);

  return (CURLcode)res;
}

CURLcode operate(struct GlobalConfig *config, int argc, argv_item_t argv[])
{
  CURLcode result = CURLE_OK;

  /* Setup proper locale from environment */
#ifdef HAVE_SETLOCALE
  setlocale(LC_ALL, "");
#endif

  /* Parse .curlrc if necessary */
  if((argc == 1) || (!curlx_strequal(argv[1], "-q"))) {
    parseconfig(NULL, config); /* ignore possible failure */

    /* If we had no arguments then make sure a url was specified in .curlrc */
    if((argc < 2) && (!config->first->url_list)) {
      helpf(config->errors, NULL);
      result = CURLE_FAILED_INIT;
    }
  }

  if(!result) {
    /* Parse the command line arguments */
    ParameterError res = parse_args(config, argc, argv);
    if(res) {
      result = CURLE_OK;

      /* Check if we were asked for the help */
      if(res == PARAM_HELP_REQUESTED)
        tool_help();
      /* Check if we were asked for the manual */
      else if(res == PARAM_MANUAL_REQUESTED)
        hugehelp();
      /* Check if we were asked for the version information */
      else if(res == PARAM_VERSION_INFO_REQUESTED)
        tool_version_info();
      /* Check if we were asked to list the SSL engines */
      else if(res == PARAM_ENGINES_REQUESTED)
        tool_list_engines(config->easy);
      else
        result = CURLE_FAILED_INIT;
    }
    else {
#ifndef CURL_DISABLE_LIBCURL_OPTION
      /* Initialise the libcurl source output */
      result = easysrc_init();
#endif

      /* Perform the main operations */
      if(!result) {
        size_t count = 0;
        struct OperationConfig *operation = config->first;

        /* Get the required aguments for each operation */
        while(!result && operation) {
          result = get_args(operation, count++);

          operation = operation->next;
        }

        /* Set the current operation pointer */
        config->current = config->first;

        /* Perform each operation */
        while(!result && config->current) {
          result = operate_do(config, config->current);

          config->current = config->current->next;
        }

#ifndef CURL_DISABLE_LIBCURL_OPTION
        /* Cleanup the libcurl source output */
        easysrc_cleanup();

        /* Dump the libcurl code if previously enabled */
        dumpeasysrc(config);
#endif
      }
      else
        helpf(config->errors, "out of memory\n");
    }
  }

  return result;
}
