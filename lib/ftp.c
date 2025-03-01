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

#include "curl_setup.h"

#ifndef CURL_DISABLE_FTP

#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif
#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif
#ifdef __VMS
#include <in.h>
#include <inet.h>
#endif

#include <curl/curl.h>
#include "urldata.h"
#include "sendf.h"
#include "if2ip.h"
#include "hostip.h"
#include "progress.h"
#include "transfer.h"
#include "escape.h"
#include "http.h" /* for HTTP proxy tunnel stuff */
#include "ftp.h"
#include "fileinfo.h"
#include "ftplistparser.h"
#include "curl_range.h"
#include "curl_krb5.h"
#include "strcase.h"
#include "vtls/vtls.h"
#include "cfilters.h"
#include "cf-socket.h"
#include "connect.h"
#include "strerror.h"
#include "inet_ntop.h"
#include "inet_pton.h"
#include "select.h"
#include "parsedate.h" /* for the week day and month names */
#include "sockaddr.h" /* required for Curl_sockaddr_storage */
#include "multiif.h"
#include "url.h"
#include "speedcheck.h"
#include "warnless.h"
#include "http_proxy.h"
#include "socks.h"
#include "strdup.h"
#include "strparse.h"
/* The last 3 #include files should be in this order */
#include "curl_printf.h"
#include "curl_memory.h"
#include "memdebug.h"

#ifndef NI_MAXHOST
#define NI_MAXHOST 1025
#endif
#ifndef INET_ADDRSTRLEN
#define INET_ADDRSTRLEN 16
#endif

/* macro to check for a three-digit ftp status code at the start of the
   given string */
#define STATUSCODE(line) (ISDIGIT(line[0]) && ISDIGIT(line[1]) &&       \
                          ISDIGIT(line[2]))

/* macro to check for the last line in an FTP server response */
#define LASTLINE(line) (STATUSCODE(line) && (' ' == line[3]))

#ifdef CURL_DISABLE_VERBOSE_STRINGS
#define ftp_pasv_verbose(a,b,c,d)  Curl_nop_stmt
#define FTP_CSTATE(c)   ""
#define FTP_DSTATE(d)   ""
#else /* CURL_DISABLE_VERBOSE_STRINGS */
  /* for tracing purposes */
static const char * const ftp_state_names[]={
  "STOP",
  "WAIT220",
  "AUTH",
  "USER",
  "PASS",
  "ACCT",
  "PBSZ",
  "PROT",
  "CCC",
  "PWD",
  "SYST",
  "NAMEFMT",
  "QUOTE",
  "RETR_PREQUOTE",
  "STOR_PREQUOTE",
  "POSTQUOTE",
  "CWD",
  "MKD",
  "MDTM",
  "TYPE",
  "LIST_TYPE",
  "RETR_TYPE",
  "STOR_TYPE",
  "SIZE",
  "RETR_SIZE",
  "STOR_SIZE",
  "REST",
  "RETR_REST",
  "PORT",
  "PRET",
  "PASV",
  "LIST",
  "RETR",
  "STOR",
  "QUIT"
};
#define FTP_CSTATE(c)   ((c)? ftp_state_names[(c)->proto.ftpc.state] : "???")
#define FTP_DSTATE(d)   (((d) && (d)->conn)? \
                         ftp_state_names[(d)->conn->proto.ftpc.state] : "???")

#endif /* !CURL_DISABLE_VERBOSE_STRINGS */

/* This is the ONLY way to change FTP state! */
static void _ftp_state(struct Curl_easy *data,
                       ftpstate newstate
#ifdef DEBUGBUILD
                       , int lineno
#endif
  )
{
  struct connectdata *conn = data->conn;
  struct ftp_conn *ftpc = &conn->proto.ftpc;

#if defined(CURL_DISABLE_VERBOSE_STRINGS)
#ifdef DEBUGBUILD
  (void)lineno;
#endif
#else /* CURL_DISABLE_VERBOSE_STRINGS */
  if(ftpc->state != newstate)
#ifdef DEBUGBUILD
    CURL_TRC_FTP(data, "[%s] -> [%s] (line %d)", FTP_DSTATE(data),
                 ftp_state_names[newstate], lineno);
#else
    CURL_TRC_FTP(data, "[%s] -> [%s]", FTP_DSTATE(data),
                 ftp_state_names[newstate]);
#endif
#endif /* !CURL_DISABLE_VERBOSE_STRINGS */

  ftpc->state = newstate;
}


/* Local API functions */
#ifndef DEBUGBUILD
#define ftp_state(x,y) _ftp_state(x,y)
#else /* !DEBUGBUILD */
#define ftp_state(x,y) _ftp_state(x,y,__LINE__)
#endif /* DEBUGBUILD */

static CURLcode ftp_sendquote(struct Curl_easy *data,
                              struct connectdata *conn,
                              struct curl_slist *quote);
static CURLcode ftp_quit(struct Curl_easy *data, struct connectdata *conn);
static CURLcode ftp_parse_url_path(struct Curl_easy *data);
static CURLcode ftp_regular_transfer(struct Curl_easy *data, bool *done);
#ifndef CURL_DISABLE_VERBOSE_STRINGS
static void ftp_pasv_verbose(struct Curl_easy *data,
                             struct Curl_addrinfo *ai,
                             char *newhost, /* ASCII version */
                             int port);
#endif
static CURLcode ftp_state_prepare_transfer(struct Curl_easy *data);
static CURLcode ftp_state_mdtm(struct Curl_easy *data);
static CURLcode ftp_state_quote(struct Curl_easy *data,
                                bool init, ftpstate instate);
static CURLcode ftp_nb_type(struct Curl_easy *data,
                            struct connectdata *conn,
                            bool ascii, ftpstate newstate);
static int ftp_need_type(struct connectdata *conn,
                         bool ascii);
static CURLcode ftp_do(struct Curl_easy *data, bool *done);
static CURLcode ftp_done(struct Curl_easy *data,
                         CURLcode, bool premature);
static CURLcode ftp_connect(struct Curl_easy *data, bool *done);
static CURLcode ftp_disconnect(struct Curl_easy *data,
                               struct connectdata *conn, bool dead_connection);
static CURLcode ftp_do_more(struct Curl_easy *data, int *completed);
static CURLcode ftp_multi_statemach(struct Curl_easy *data, bool *done);
static int ftp_getsock(struct Curl_easy *data, struct connectdata *conn,
                       curl_socket_t *socks);
static int ftp_domore_getsock(struct Curl_easy *data,
                              struct connectdata *conn, curl_socket_t *socks);
static CURLcode ftp_doing(struct Curl_easy *data,
                          bool *dophase_done);
static CURLcode ftp_setup_connection(struct Curl_easy *data,
                                     struct connectdata *conn);
static CURLcode init_wc_data(struct Curl_easy *data);
static CURLcode wc_statemach(struct Curl_easy *data);
static void wc_data_dtor(void *ptr);
static CURLcode ftp_state_retr(struct Curl_easy *data, curl_off_t filesize);
static CURLcode ftp_readresp(struct Curl_easy *data,
                             int sockindex,
                             struct pingpong *pp,
                             int *ftpcode,
                             size_t *size);
static CURLcode ftp_dophase_done(struct Curl_easy *data,
                                 bool connected);

/*
 * FTP protocol handler.
 */

const struct Curl_handler Curl_handler_ftp = {
  "ftp",                           /* scheme */
  ftp_setup_connection,            /* setup_connection */
  ftp_do,                          /* do_it */
  ftp_done,                        /* done */
  ftp_do_more,                     /* do_more */
  ftp_connect,                     /* connect_it */
  ftp_multi_statemach,             /* connecting */
  ftp_doing,                       /* doing */
  ftp_getsock,                     /* proto_getsock */
  ftp_getsock,                     /* doing_getsock */
  ftp_domore_getsock,              /* domore_getsock */
  ZERO_NULL,                       /* perform_getsock */
  ftp_disconnect,                  /* disconnect */
  ZERO_NULL,                       /* write_resp */
  ZERO_NULL,                       /* write_resp_hd */
  ZERO_NULL,                       /* connection_check */
  ZERO_NULL,                       /* attach connection */
  ZERO_NULL,                       /* follow */
  PORT_FTP,                        /* defport */
  CURLPROTO_FTP,                   /* protocol */
  CURLPROTO_FTP,                   /* family */
  PROTOPT_DUAL | PROTOPT_CLOSEACTION | PROTOPT_NEEDSPWD |
  PROTOPT_NOURLQUERY | PROTOPT_PROXY_AS_HTTP |
  PROTOPT_WILDCARD /* flags */
};


#ifdef USE_SSL
/*
 * FTPS protocol handler.
 */

const struct Curl_handler Curl_handler_ftps = {
  "ftps",                          /* scheme */
  ftp_setup_connection,            /* setup_connection */
  ftp_do,                          /* do_it */
  ftp_done,                        /* done */
  ftp_do_more,                     /* do_more */
  ftp_connect,                     /* connect_it */
  ftp_multi_statemach,             /* connecting */
  ftp_doing,                       /* doing */
  ftp_getsock,                     /* proto_getsock */
  ftp_getsock,                     /* doing_getsock */
  ftp_domore_getsock,              /* domore_getsock */
  ZERO_NULL,                       /* perform_getsock */
  ftp_disconnect,                  /* disconnect */
  ZERO_NULL,                       /* write_resp */
  ZERO_NULL,                       /* write_resp_hd */
  ZERO_NULL,                       /* connection_check */
  ZERO_NULL,                       /* attach connection */
  ZERO_NULL,                       /* follow */
  PORT_FTPS,                       /* defport */
  CURLPROTO_FTPS,                  /* protocol */
  CURLPROTO_FTP,                   /* family */
  PROTOPT_SSL | PROTOPT_DUAL | PROTOPT_CLOSEACTION |
  PROTOPT_NEEDSPWD | PROTOPT_NOURLQUERY | PROTOPT_WILDCARD /* flags */
};
#endif

static void close_secondarysocket(struct Curl_easy *data)
{
  CURL_TRC_FTP(data, "[%s] closing DATA connection", FTP_DSTATE(data));
  Curl_conn_close(data, SECONDARYSOCKET);
  Curl_conn_cf_discard_all(data, data->conn, SECONDARYSOCKET);
}

/*
 * NOTE: back in the old days, we added code in the FTP code that made NOBODY
 * requests on files respond with headers passed to the client/stdout that
 * looked like HTTP ones.
 *
 * This approach is not elegant, it causes confusion and is error-prone. It is
 * subject for removal at the next (or at least a future) soname bump. Until
 * then you can test the effects of the removal by undefining the following
 * define named CURL_FTP_HTTPSTYLE_HEAD.
 */
#define CURL_FTP_HTTPSTYLE_HEAD 1

static void freedirs(struct ftp_conn *ftpc)
{
  if(ftpc->dirs) {
    int i;
    for(i = 0; i < ftpc->dirdepth; i++) {
      free(ftpc->dirs[i]);
      ftpc->dirs[i] = NULL;
    }
    free(ftpc->dirs);
    ftpc->dirs = NULL;
    ftpc->dirdepth = 0;
  }
  Curl_safefree(ftpc->file);

  /* no longer of any use */
  Curl_safefree(ftpc->newhost);
}

#ifdef CURL_PREFER_LF_LINEENDS
/***********************************************************************
 *
 * Lineend Conversions
 * On ASCII transfers, e.g. directory listings, we might get lines
 * ending in '\r\n' and we prefer just '\n'.
 * We might also get a lonely '\r' which we convert into a '\n'.
 */
struct ftp_cw_lc_ctx {
  struct Curl_cwriter super;
  bool newline_pending;
};

static CURLcode ftp_cw_lc_write(struct Curl_easy *data,
                                struct Curl_cwriter *writer, int type,
                                const char *buf, size_t blen)
{
  static const char nl = '\n';
  struct ftp_cw_lc_ctx *ctx = writer->ctx;

  if(!(type & CLIENTWRITE_BODY) ||
     data->conn->proto.ftpc.transfertype != 'A')
    return Curl_cwriter_write(data, writer->next, type, buf, blen);

  /* ASCII mode BODY data, convert lineends */
  while(blen) {
    /* do not pass EOS when writing parts */
    int chunk_type = (type & ~CLIENTWRITE_EOS);
    const char *cp;
    size_t chunk_len;
    CURLcode result;

    if(ctx->newline_pending) {
      if(buf[0] != '\n') {
        /* previous chunk ended in '\r' and we do not see a '\n' in this one,
         * need to write a newline. */
        result = Curl_cwriter_write(data, writer->next, chunk_type, &nl, 1);
        if(result)
          return result;
      }
      /* either we just wrote the newline or it is part of the next
       * chunk of bytes we write. */
      ctx->newline_pending = FALSE;
    }

    cp = memchr(buf, '\r', blen);
    if(!cp)
      break;

    /* write the bytes before the '\r', excluding the '\r' */
    chunk_len = cp - buf;
    if(chunk_len) {
      result = Curl_cwriter_write(data, writer->next, chunk_type,
                                  buf, chunk_len);
      if(result)
        return result;
    }
    /* skip the '\r', we now have a newline pending */
    buf = cp + 1;
    blen = blen - chunk_len - 1;
    ctx->newline_pending = TRUE;
  }

  /* Any remaining data does not contain a '\r' */
  if(blen) {
    DEBUGASSERT(!ctx->newline_pending);
    return Curl_cwriter_write(data, writer->next, type, buf, blen);
  }
  else if(type & CLIENTWRITE_EOS) {
    /* EndOfStream, if we have a trailing cr, now is the time to write it */
    if(ctx->newline_pending) {
      ctx->newline_pending = FALSE;
      return Curl_cwriter_write(data, writer->next, type, &nl, 1);
    }
    /* Always pass on the EOS type indicator */
    return Curl_cwriter_write(data, writer->next, type, buf, 0);
  }
  return CURLE_OK;
}

static const struct Curl_cwtype ftp_cw_lc = {
  "ftp-lineconv",
  NULL,
  Curl_cwriter_def_init,
  ftp_cw_lc_write,
  Curl_cwriter_def_close,
  sizeof(struct ftp_cw_lc_ctx)
};

#endif /* CURL_PREFER_LF_LINEENDS */
/***********************************************************************
 *
 * ftp_check_ctrl_on_data_wait()
 *
 */
static CURLcode ftp_check_ctrl_on_data_wait(struct Curl_easy *data)
{
  struct connectdata *conn = data->conn;
  curl_socket_t ctrl_sock = conn->sock[FIRSTSOCKET];
  struct ftp_conn *ftpc = &conn->proto.ftpc;
  struct pingpong *pp = &ftpc->pp;
  ssize_t nread;
  int ftpcode;
  bool response = FALSE;

  /* First check whether there is a cached response from server */
  if(Curl_dyn_len(&pp->recvbuf) && (*Curl_dyn_ptr(&pp->recvbuf) > '3')) {
    /* Data connection could not be established, let's return */
    infof(data, "There is negative response in cache while serv connect");
    (void)Curl_GetFTPResponse(data, &nread, &ftpcode);
    return CURLE_FTP_ACCEPT_FAILED;
  }

  if(pp->overflow)
    /* there is pending control data still in the buffer to read */
    response = TRUE;
  else {
    int socketstate = Curl_socket_check(ctrl_sock, CURL_SOCKET_BAD,
                                        CURL_SOCKET_BAD, 0);
    /* see if the connection request is already here */
    switch(socketstate) {
    case -1: /* error */
      /* let's die here */
      failf(data, "Error while waiting for server connect");
      return CURLE_FTP_ACCEPT_FAILED;
    default:
      if(socketstate & CURL_CSELECT_IN)
        response = TRUE;
      break;
    }
  }

  if(response) {
    infof(data, "Ctrl conn has data while waiting for data conn");
    if(pp->overflow > 3) {
      const char *r = Curl_dyn_ptr(&pp->recvbuf);

      DEBUGASSERT((pp->overflow + pp->nfinal) <=
                  Curl_dyn_len(&pp->recvbuf));
      /* move over the most recently handled response line */
      r += pp->nfinal;

      if(LASTLINE(r)) {
        curl_off_t status;
        if(!Curl_str_number(&r, &status, 999) && (status == 226)) {
          /* funny timing situation where we get the final message on the
             control connection before traffic on the data connection has been
             noticed. Leave the 226 in there and use this as a trigger to read
             the data socket. */
          infof(data, "Got 226 before data activity");
          return CURLE_OK;
        }
      }
    }

    (void)Curl_GetFTPResponse(data, &nread, &ftpcode);

    infof(data, "FTP code: %03d", ftpcode);

    if(ftpcode/100 > 3)
      return CURLE_FTP_ACCEPT_FAILED;

    return CURLE_WEIRD_SERVER_REPLY;
  }

  return CURLE_OK;
}

/***********************************************************************
 *
 * InitiateTransfer()
 *
 * After connection from server is accepted this function is called to
 * setup transfer parameters and initiate the data transfer.
 *
 */
static CURLcode InitiateTransfer(struct Curl_easy *data)
{
  CURLcode result = CURLE_OK;
  struct connectdata *conn = data->conn;
  bool connected;

  CURL_TRC_FTP(data, "InitiateTransfer()");
  result = Curl_conn_connect(data, SECONDARYSOCKET, TRUE, &connected);
  if(result || !connected)
    return result;

  if(conn->proto.ftpc.state_saved == FTP_STOR) {
    /* When we know we are uploading a specified file, we can get the file
       size prior to the actual upload. */
    Curl_pgrsSetUploadSize(data, data->state.infilesize);

    /* set the SO_SNDBUF for the secondary socket for those who need it */
    Curl_sndbuf_init(conn->sock[SECONDARYSOCKET]);

    /* FTP upload, shutdown DATA, ignore shutdown errors, as we rely
     * on the server response on the CONTROL connection. */
    Curl_xfer_setup2(data, CURL_XFER_SEND, -1, TRUE, TRUE);
  }
  else {
    /* FTP download, shutdown, do not ignore errors */
    Curl_xfer_setup2(data, CURL_XFER_RECV,
                     conn->proto.ftpc.retr_size_saved, TRUE, FALSE);
  }

  conn->proto.ftpc.pp.pending_resp = TRUE; /* expect server response */
  ftp_state(data, FTP_STOP);

  return CURLE_OK;
}

static bool ftp_endofresp(struct Curl_easy *data, struct connectdata *conn,
                          const char *line, size_t len, int *code)
{
  curl_off_t status;
  (void)data;
  (void)conn;

  if((len > 3) && LASTLINE(line) && !Curl_str_number(&line, &status, 999)) {
    *code = (int)status;
    return TRUE;
  }

  return FALSE;
}

static CURLcode ftp_readresp(struct Curl_easy *data,
                             int sockindex,
                             struct pingpong *pp,
                             int *ftpcode, /* return the ftp-code if done */
                             size_t *size) /* size of the response */
{
  int code;
  CURLcode result = Curl_pp_readresp(data, sockindex, pp, &code, size);

#ifdef HAVE_GSSAPI
  {
    struct connectdata *conn = data->conn;
    char * const buf = Curl_dyn_ptr(&data->conn->proto.ftpc.pp.recvbuf);

    /* handle the security-oriented responses 6xx ***/
    switch(code) {
    case 631:
      code = Curl_sec_read_msg(data, conn, buf, PROT_SAFE);
      break;
    case 632:
      code = Curl_sec_read_msg(data, conn, buf, PROT_PRIVATE);
      break;
    case 633:
      code = Curl_sec_read_msg(data, conn, buf, PROT_CONFIDENTIAL);
      break;
    default:
      /* normal ftp stuff we pass through! */
      break;
    }
  }
#endif

  /* store the latest code for later retrieval */
  data->info.httpcode = code;

  if(ftpcode)
    *ftpcode = code;

  if(421 == code) {
    /* 421 means "Service not available, closing control connection." and FTP
     * servers use it to signal that idle session timeout has been exceeded.
     * If we ignored the response, it could end up hanging in some cases.
     *
     * This response code can come at any point so having it treated
     * generically is a good idea.
     */
    infof(data, "We got a 421 - timeout");
    ftp_state(data, FTP_STOP);
    return CURLE_OPERATION_TIMEDOUT;
  }

  return result;
}

/* --- parse FTP server responses --- */

/*
 * Curl_GetFTPResponse() is a BLOCKING function to read the full response
 * from a server after a command.
 *
 */

CURLcode Curl_GetFTPResponse(struct Curl_easy *data,
                             ssize_t *nreadp, /* return number of bytes read */
                             int *ftpcode) /* return the ftp-code */
{
  /*
   * We cannot read just one byte per read() and then go back to select() as
   * the OpenSSL read() does not grok that properly.
   *
   * Alas, read as much as possible, split up into lines, use the ending
   * line in a response or continue reading.  */

  struct connectdata *conn = data->conn;
  curl_socket_t sockfd = conn->sock[FIRSTSOCKET];
  CURLcode result = CURLE_OK;
  struct ftp_conn *ftpc = &conn->proto.ftpc;
  struct pingpong *pp = &ftpc->pp;
  size_t nread;
  int cache_skip = 0;
  int value_to_be_ignored = 0;

  CURL_TRC_FTP(data, "getFTPResponse start");

  if(ftpcode)
    *ftpcode = 0; /* 0 for errors */
  else
    /* make the pointer point to something for the rest of this function */
    ftpcode = &value_to_be_ignored;

  *nreadp = 0;

  while(!*ftpcode && !result) {
    /* check and reset timeout value every lap */
    timediff_t timeout = Curl_pp_state_timeout(data, pp, FALSE);
    timediff_t interval_ms;

    if(timeout <= 0) {
      failf(data, "FTP response timeout");
      return CURLE_OPERATION_TIMEDOUT; /* already too little time */
    }

    interval_ms = 1000;  /* use 1 second timeout intervals */
    if(timeout < interval_ms)
      interval_ms = timeout;

    /*
     * Since this function is blocking, we need to wait here for input on the
     * connection and only then we call the response reading function. We do
     * timeout at least every second to make the timeout check run.
     *
     * A caution here is that the ftp_readresp() function has a cache that may
     * contain pieces of a response from the previous invoke and we need to
     * make sure we do not just wait for input while there is unhandled data in
     * that cache. But also, if the cache is there, we call ftp_readresp() and
     * the cache was not good enough to continue we must not just busy-loop
     * around this function.
     *
     */

    if(Curl_dyn_len(&pp->recvbuf) && (cache_skip < 2)) {
      /*
       * There is a cache left since before. We then skipping the wait for
       * socket action, unless this is the same cache like the previous round
       * as then the cache was deemed not enough to act on and we then need to
       * wait for more data anyway.
       */
    }
    else if(!Curl_conn_data_pending(data, FIRSTSOCKET)) {
      curl_socket_t wsock = Curl_pp_needs_flush(data, pp) ?
        sockfd : CURL_SOCKET_BAD;
      int ev = Curl_socket_check(sockfd, CURL_SOCKET_BAD, wsock, interval_ms);
      if(ev < 0) {
        failf(data, "FTP response aborted due to select/poll error: %d",
              SOCKERRNO);
        return CURLE_RECV_ERROR;
      }
      else if(ev == 0) {
        if(Curl_pgrsUpdate(data))
          return CURLE_ABORTED_BY_CALLBACK;
        continue; /* just continue in our loop for the timeout duration */
      }
    }

    if(Curl_pp_needs_flush(data, pp)) {
      result = Curl_pp_flushsend(data, pp);
      if(result)
        break;
    }

    result = ftp_readresp(data, FIRSTSOCKET, pp, ftpcode, &nread);
    if(result)
      break;

    if(!nread && Curl_dyn_len(&pp->recvbuf))
      /* bump cache skip counter as on repeated skips we must wait for more
         data */
      cache_skip++;
    else
      /* when we got data or there is no cache left, we reset the cache skip
         counter */
      cache_skip = 0;

    *nreadp += nread;

  } /* while there is buffer left and loop is requested */

  pp->pending_resp = FALSE;
  CURL_TRC_FTP(data, "getFTPResponse -> result=%d, nread=%zd, ftpcode=%d",
               result, *nreadp, *ftpcode);

  return result;
}

static CURLcode ftp_state_user(struct Curl_easy *data,
                               struct connectdata *conn)
{
  CURLcode result = Curl_pp_sendf(data,
                                  &conn->proto.ftpc.pp, "USER %s",
                                  conn->user ? conn->user : "");
  if(!result) {
    struct ftp_conn *ftpc = &conn->proto.ftpc;
    ftpc->ftp_trying_alternative = FALSE;
    ftp_state(data, FTP_USER);
  }
  return result;
}

static CURLcode ftp_state_pwd(struct Curl_easy *data,
                              struct connectdata *conn)
{
  CURLcode result = Curl_pp_sendf(data, &conn->proto.ftpc.pp, "%s", "PWD");
  if(!result)
    ftp_state(data, FTP_PWD);

  return result;
}

/* For the FTP "protocol connect" and "doing" phases only */
static int ftp_getsock(struct Curl_easy *data,
                       struct connectdata *conn,
                       curl_socket_t *socks)
{
  return Curl_pp_getsock(data, &conn->proto.ftpc.pp, socks);
}

/* For the FTP "DO_MORE" phase only */
static int ftp_domore_getsock(struct Curl_easy *data,
                              struct connectdata *conn, curl_socket_t *socks)
{
  struct ftp_conn *ftpc = &conn->proto.ftpc;
  (void)data;

  /* When in DO_MORE state, we could be either waiting for us to connect to a
   * remote site, or we could wait for that site to connect to us. Or just
   * handle ordinary commands.
   */
  CURL_TRC_FTP(data, "[%s] ftp_domore_getsock()", FTP_DSTATE(data));

  if(FTP_STOP == ftpc->state) {
    /* if stopped and still in this state, then we are also waiting for a
       connect on the secondary connection */
    DEBUGASSERT(conn->sock[SECONDARYSOCKET] != CURL_SOCKET_BAD ||
               (conn->cfilter[SECONDARYSOCKET] &&
                !Curl_conn_is_connected(conn, SECONDARYSOCKET)));
    socks[0] = conn->sock[FIRSTSOCKET];
    /* An unconnected SECONDARY will add its socket by itself
     * via its adjust_pollset() */
    return GETSOCK_READSOCK(0);
  }
  return Curl_pp_getsock(data, &conn->proto.ftpc.pp, socks);
}

/* This is called after the FTP_QUOTE state is passed.

   ftp_state_cwd() sends the range of CWD commands to the server to change to
   the correct directory. It may also need to send MKD commands to create
   missing ones, if that option is enabled.
*/
static CURLcode ftp_state_cwd(struct Curl_easy *data,
                              struct connectdata *conn)
{
  CURLcode result = CURLE_OK;
  struct ftp_conn *ftpc = &conn->proto.ftpc;

  if(ftpc->cwddone)
    /* already done and fine */
    result = ftp_state_mdtm(data);
  else {
    /* FTPFILE_NOCWD with full path: expect ftpc->cwddone! */
    DEBUGASSERT((data->set.ftp_filemethod != FTPFILE_NOCWD) ||
                !(ftpc->dirdepth && ftpc->dirs[0][0] == '/'));

    ftpc->count2 = 0; /* count2 counts failed CWDs */

    if(conn->bits.reuse && ftpc->entrypath &&
       /* no need to go to entrypath when we have an absolute path */
       !(ftpc->dirdepth && ftpc->dirs[0][0] == '/')) {
      /* This is a reused connection. Since we change directory to where the
         transfer is taking place, we must first get back to the original dir
         where we ended up after login: */
      ftpc->cwdcount = 0; /* we count this as the first path, then we add one
                             for all upcoming ones in the ftp->dirs[] array */
      result = Curl_pp_sendf(data, &ftpc->pp, "CWD %s", ftpc->entrypath);
      if(!result)
        ftp_state(data, FTP_CWD);
    }
    else {
      if(ftpc->dirdepth) {
        ftpc->cwdcount = 1;
        /* issue the first CWD, the rest is sent when the CWD responses are
           received... */
        result = Curl_pp_sendf(data, &ftpc->pp, "CWD %s",
                               ftpc->dirs[ftpc->cwdcount -1]);
        if(!result)
          ftp_state(data, FTP_CWD);
      }
      else {
        /* No CWD necessary */
        result = ftp_state_mdtm(data);
      }
    }
  }
  return result;
}

typedef enum {
  EPRT,
  PORT,
  DONE
} ftpport;

static CURLcode ftp_state_use_port(struct Curl_easy *data,
                                   ftpport fcmd) /* start with this */
{
  CURLcode result = CURLE_FTP_PORT_FAILED;
  struct connectdata *conn = data->conn;
  struct ftp_conn *ftpc = &conn->proto.ftpc;
  curl_socket_t portsock = CURL_SOCKET_BAD;
  char myhost[MAX_IPADR_LEN + 1] = "";

  struct Curl_sockaddr_storage ss;
  struct Curl_addrinfo *res, *ai;
  curl_socklen_t sslen;
  char hbuf[NI_MAXHOST];
  struct sockaddr *sa = (struct sockaddr *)&ss;
  struct sockaddr_in * const sa4 = (void *)sa;
#ifdef USE_IPV6
  struct sockaddr_in6 * const sa6 = (void *)sa;
#endif
  static const char mode[][5] = { "EPRT", "PORT" };
  enum resolve_t rc;
  int error;
  char *host = NULL;
  char *string_ftpport = data->set.str[STRING_FTPPORT];
  struct Curl_dns_entry *dns_entry = NULL;
  unsigned short port_min = 0;
  unsigned short port_max = 0;
  unsigned short port;
  bool possibly_non_local = TRUE;
  char buffer[STRERROR_LEN];
  char *addr = NULL;
  size_t addrlen = 0;
  char ipstr[50];

  /* Step 1, figure out what is requested,
   * accepted format :
   * (ipv4|ipv6|domain|interface)?(:port(-range)?)?
   */

  if(data->set.str[STRING_FTPPORT] &&
     (strlen(data->set.str[STRING_FTPPORT]) > 1)) {
    char *ip_end = NULL;

#ifdef USE_IPV6
    if(*string_ftpport == '[') {
      /* [ipv6]:port(-range) */
      char *ip_start = string_ftpport + 1;
      ip_end = strchr(ip_start, ']');
      if(ip_end) {
        addrlen = ip_end - ip_start;
        addr = ip_start;
      }
    }
    else
#endif
      if(*string_ftpport == ':') {
        /* :port */
        ip_end = string_ftpport;
      }
      else {
        ip_end = strchr(string_ftpport, ':');
        addr = string_ftpport;
        if(ip_end) {
          /* either ipv6 or (ipv4|domain|interface):port(-range) */
          addrlen = ip_end - string_ftpport;
#ifdef USE_IPV6
          if(Curl_inet_pton(AF_INET6, string_ftpport, &sa6->sin6_addr) == 1) {
            /* ipv6 */
            port_min = port_max = 0;
            ip_end = NULL; /* this got no port ! */
          }
#endif
        }
        else
          /* ipv4|interface */
          addrlen = strlen(string_ftpport);
      }

    /* parse the port */
    if(ip_end) {
      const char *portp = strchr(ip_end, ':');
      if(portp) {
        curl_off_t start;
        curl_off_t end;
        portp++;
        if(!Curl_str_number(&portp, &start, 0xffff)) {
          /* got the first number */
          port_min = (unsigned short)start;
          if(!Curl_str_single(&portp, '-')) {
            /* got the dash */
            if(!Curl_str_number(&portp, &end, 0xffff))
              /* got the second number */
              port_max = (unsigned short)end;
          }
        }
        else
          port_max = port_min;
      }
    }

    /* correct errors like:
     *  :1234-1230
     *  :-4711,  in this case port_min is (unsigned)-1,
     *           therefore port_min > port_max for all cases
     *           but port_max = (unsigned)-1
     */
    if(port_min > port_max)
      port_min = port_max = 0;

    if(addrlen) {
      DEBUGASSERT(addr);
      if(addrlen >= sizeof(ipstr))
        goto out;
      memcpy(ipstr, addr, addrlen);
      ipstr[addrlen] = 0;

      /* attempt to get the address of the given interface name */
      switch(Curl_if2ip(conn->remote_addr->family,
#ifdef USE_IPV6
                        Curl_ipv6_scope(&conn->remote_addr->curl_sa_addr),
                        conn->scope_id,
#endif
                        ipstr, hbuf, sizeof(hbuf))) {
        case IF2IP_NOT_FOUND:
          /* not an interface, use the given string as hostname instead */
          host = ipstr;
          break;
        case IF2IP_AF_NOT_SUPPORTED:
          goto out;
        case IF2IP_FOUND:
          host = hbuf; /* use the hbuf for hostname */
          break;
      }
    }
    else
      /* there was only a port(-range) given, default the host */
      host = NULL;
  } /* data->set.ftpport */

  if(!host) {
    const char *r;
    /* not an interface and not a hostname, get default by extracting
       the IP from the control connection */
    sslen = sizeof(ss);
    if(getsockname(conn->sock[FIRSTSOCKET], sa, &sslen)) {
      failf(data, "getsockname() failed: %s",
            Curl_strerror(SOCKERRNO, buffer, sizeof(buffer)));
      goto out;
    }
    switch(sa->sa_family) {
#ifdef USE_IPV6
    case AF_INET6:
      r = Curl_inet_ntop(sa->sa_family, &sa6->sin6_addr, hbuf, sizeof(hbuf));
      break;
#endif
    default:
      r = Curl_inet_ntop(sa->sa_family, &sa4->sin_addr, hbuf, sizeof(hbuf));
      break;
    }
    if(!r) {
      goto out;
    }
    host = hbuf; /* use this hostname */
    possibly_non_local = FALSE; /* we know it is local now */
  }

  /* resolv ip/host to ip */
  rc = Curl_resolv(data, host, 0, FALSE, &dns_entry);
  if(rc == CURLRESOLV_PENDING)
    (void)Curl_resolver_wait_resolv(data, &dns_entry);
  if(dns_entry) {
    res = dns_entry->addr;
  }
  else
    res = NULL; /* failure! */

  if(!res) {
    failf(data, "failed to resolve the address provided to PORT: %s", host);
    goto out;
  }

  host = NULL;

  /* step 2, create a socket for the requested address */
  error = 0;
  for(ai = res; ai; ai = ai->ai_next) {
    if(Curl_socket_open(data, ai, NULL, conn->transport, &portsock)) {
      error = SOCKERRNO;
      continue;
    }
    break;
  }
  if(!ai) {
    failf(data, "socket failure: %s",
          Curl_strerror(error, buffer, sizeof(buffer)));
    goto out;
  }
  CURL_TRC_FTP(data, "[%s] ftp_state_use_port(), opened socket",
               FTP_DSTATE(data));

  /* step 3, bind to a suitable local address */

  memcpy(sa, ai->ai_addr, ai->ai_addrlen);
  sslen = ai->ai_addrlen;

  for(port = port_min; port <= port_max;) {
    if(sa->sa_family == AF_INET)
      sa4->sin_port = htons(port);
#ifdef USE_IPV6
    else
      sa6->sin6_port = htons(port);
#endif
    /* Try binding the given address. */
    if(bind(portsock, sa, sslen) ) {
      /* It failed. */
      error = SOCKERRNO;
      if(possibly_non_local && (error == EADDRNOTAVAIL)) {
        /* The requested bind address is not local. Use the address used for
         * the control connection instead and restart the port loop
         */
        infof(data, "bind(port=%hu) on non-local address failed: %s", port,
              Curl_strerror(error, buffer, sizeof(buffer)));

        sslen = sizeof(ss);
        if(getsockname(conn->sock[FIRSTSOCKET], sa, &sslen)) {
          failf(data, "getsockname() failed: %s",
                Curl_strerror(SOCKERRNO, buffer, sizeof(buffer)));
          goto out;
        }
        port = port_min;
        possibly_non_local = FALSE; /* do not try this again */
        continue;
      }
      if(error != EADDRINUSE && error != EACCES) {
        failf(data, "bind(port=%hu) failed: %s", port,
              Curl_strerror(error, buffer, sizeof(buffer)));
        goto out;
      }
    }
    else
      break;

    port++;
  }

  /* maybe all ports were in use already */
  if(port > port_max) {
    failf(data, "bind() failed, we ran out of ports");
    goto out;
  }

  /* get the name again after the bind() so that we can extract the
     port number it uses now */
  sslen = sizeof(ss);
  if(getsockname(portsock, sa, &sslen)) {
    failf(data, "getsockname() failed: %s",
          Curl_strerror(SOCKERRNO, buffer, sizeof(buffer)));
    goto out;
  }
  CURL_TRC_FTP(data, "[%s] ftp_state_use_port(), socket bound to port %d",
               FTP_DSTATE(data), port);

  /* step 4, listen on the socket */

  if(listen(portsock, 1)) {
    failf(data, "socket failure: %s",
          Curl_strerror(SOCKERRNO, buffer, sizeof(buffer)));
    goto out;
  }
  CURL_TRC_FTP(data, "[%s] ftp_state_use_port(), listening on %d",
               FTP_DSTATE(data), port);

  /* step 5, send the proper FTP command */

  /* get a plain printable version of the numerical address to work with
     below */
  Curl_printable_address(ai, myhost, sizeof(myhost));

#ifdef USE_IPV6
  if(!conn->bits.ftp_use_eprt && conn->bits.ipv6)
    /* EPRT is disabled but we are connected to a IPv6 host, so we ignore the
       request and enable EPRT again! */
    conn->bits.ftp_use_eprt = TRUE;
#endif

  for(; fcmd != DONE; fcmd++) {

    if(!conn->bits.ftp_use_eprt && (EPRT == fcmd))
      /* if disabled, goto next */
      continue;

    if((PORT == fcmd) && sa->sa_family != AF_INET)
      /* PORT is IPv4 only */
      continue;

    switch(sa->sa_family) {
    case AF_INET:
      port = ntohs(sa4->sin_port);
      break;
#ifdef USE_IPV6
    case AF_INET6:
      port = ntohs(sa6->sin6_port);
      break;
#endif
    default:
      continue; /* might as well skip this */
    }

    if(EPRT == fcmd) {
      /*
       * Two fine examples from RFC2428;
       *
       * EPRT |1|132.235.1.2|6275|
       *
       * EPRT |2|1080::8:800:200C:417A|5282|
       */

      result = Curl_pp_sendf(data, &ftpc->pp, "%s |%d|%s|%hu|", mode[fcmd],
                             sa->sa_family == AF_INET ? 1 : 2,
                             myhost, port);
      if(result) {
        failf(data, "Failure sending EPRT command: %s",
              curl_easy_strerror(result));
        goto out;
      }
      break;
    }
    if(PORT == fcmd) {
      /* large enough for [IP address],[num],[num] */
      char target[sizeof(myhost) + 20];
      char *source = myhost;
      char *dest = target;

      /* translate x.x.x.x to x,x,x,x */
      while(*source) {
        if(*source == '.')
          *dest = ',';
        else
          *dest = *source;
        dest++;
        source++;
      }
      *dest = 0;
      msnprintf(dest, 20, ",%d,%d", (int)(port >> 8), (int)(port & 0xff));

      result = Curl_pp_sendf(data, &ftpc->pp, "%s %s", mode[fcmd], target);
      if(result) {
        failf(data, "Failure sending PORT command: %s",
              curl_easy_strerror(result));
        goto out;
      }
      break;
    }
  }

  /* store which command was sent */
  ftpc->count1 = fcmd;
  ftp_state(data, FTP_PORT);

  /* Replace any filter on SECONDARY with one listening on this socket */
  result = Curl_conn_tcp_listen_set(data, conn, SECONDARYSOCKET, &portsock);
  if(!result)
    portsock = CURL_SOCKET_BAD; /* now held in filter */

out:
  /* If we looked up a dns_entry, now is the time to safely release it */
  if(dns_entry)
    Curl_resolv_unlink(data, &dns_entry);
  if(result) {
    ftp_state(data, FTP_STOP);
  }
  else {
    /* successfully setup the list socket filter. Do we need more? */
    if(conn->bits.ftp_use_data_ssl && data->set.ftp_use_port &&
       !Curl_conn_is_ssl(conn, SECONDARYSOCKET)) {
      result = Curl_ssl_cfilter_add(data, conn, SECONDARYSOCKET);
    }
    data->conn->bits.do_more = FALSE;
    Curl_pgrsTime(data, TIMER_STARTACCEPT);
    Curl_expire(data, data->set.accepttimeout ?
                data->set.accepttimeout: DEFAULT_ACCEPT_TIMEOUT,
                EXPIRE_FTP_ACCEPT);
  }
  if(portsock != CURL_SOCKET_BAD)
    Curl_socket_close(data, conn, portsock);
  return result;
}

static CURLcode ftp_state_use_pasv(struct Curl_easy *data,
                                   struct connectdata *conn)
{
  struct ftp_conn *ftpc = &conn->proto.ftpc;
  CURLcode result = CURLE_OK;
  /*
    Here's the executive summary on what to do:

    PASV is RFC959, expect:
    227 Entering Passive Mode (a1,a2,a3,a4,p1,p2)

    LPSV is RFC1639, expect:
    228 Entering Long Passive Mode (4,4,a1,a2,a3,a4,2,p1,p2)

    EPSV is RFC2428, expect:
    229 Entering Extended Passive Mode (|||port|)

  */

  static const char mode[][5] = { "EPSV", "PASV" };
  int modeoff;

#ifdef PF_INET6
  if(!conn->bits.ftp_use_epsv && conn->bits.ipv6)
    /* EPSV is disabled but we are connected to a IPv6 host, so we ignore the
       request and enable EPSV again! */
    conn->bits.ftp_use_epsv = TRUE;
#endif

  modeoff = conn->bits.ftp_use_epsv ? 0 : 1;

  result = Curl_pp_sendf(data, &ftpc->pp, "%s", mode[modeoff]);
  if(!result) {
    ftpc->count1 = modeoff;
    ftp_state(data, FTP_PASV);
    infof(data, "Connect data stream passively");
  }
  return result;
}

/*
 * ftp_state_prepare_transfer() starts PORT, PASV or PRET etc.
 *
 * REST is the last command in the chain of commands when a "head"-like
 * request is made. Thus, if an actual transfer is to be made this is where we
 * take off for real.
 */
static CURLcode ftp_state_prepare_transfer(struct Curl_easy *data)
{
  CURLcode result = CURLE_OK;
  struct FTP *ftp = data->req.p.ftp;
  struct connectdata *conn = data->conn;

  if(ftp->transfer != PPTRANSFER_BODY) {
    /* does not transfer any data */

    /* still possibly do PRE QUOTE jobs */
    ftp_state(data, FTP_RETR_PREQUOTE);
    result = ftp_state_quote(data, TRUE, FTP_RETR_PREQUOTE);
  }
  else if(data->set.ftp_use_port) {
    /* We have chosen to use the PORT (or similar) command */
    result = ftp_state_use_port(data, EPRT);
  }
  else {
    /* We have chosen (this is default) to use the PASV (or similar) command */
    if(data->set.ftp_use_pret) {
      /* The user has requested that we send a PRET command
         to prepare the server for the upcoming PASV */
      struct ftp_conn *ftpc = &conn->proto.ftpc;
      if(!conn->proto.ftpc.file)
        result = Curl_pp_sendf(data, &ftpc->pp, "PRET %s",
                               data->set.str[STRING_CUSTOMREQUEST] ?
                               data->set.str[STRING_CUSTOMREQUEST] :
                               (data->state.list_only ? "NLST" : "LIST"));
      else if(data->state.upload)
        result = Curl_pp_sendf(data, &ftpc->pp, "PRET STOR %s",
                               conn->proto.ftpc.file);
      else
        result = Curl_pp_sendf(data, &ftpc->pp, "PRET RETR %s",
                               conn->proto.ftpc.file);
      if(!result)
        ftp_state(data, FTP_PRET);
    }
    else
      result = ftp_state_use_pasv(data, conn);
  }
  return result;
}

static CURLcode ftp_state_rest(struct Curl_easy *data,
                               struct connectdata *conn)
{
  CURLcode result = CURLE_OK;
  struct FTP *ftp = data->req.p.ftp;
  struct ftp_conn *ftpc = &conn->proto.ftpc;

  if((ftp->transfer != PPTRANSFER_BODY) && ftpc->file) {
    /* if a "head"-like request is being made (on a file) */

    /* Determine if server can respond to REST command and therefore
       whether it supports range */
    result = Curl_pp_sendf(data, &ftpc->pp, "REST %d", 0);
    if(!result)
      ftp_state(data, FTP_REST);
  }
  else
    result = ftp_state_prepare_transfer(data);

  return result;
}

static CURLcode ftp_state_size(struct Curl_easy *data,
                               struct connectdata *conn)
{
  CURLcode result = CURLE_OK;
  struct FTP *ftp = data->req.p.ftp;
  struct ftp_conn *ftpc = &conn->proto.ftpc;

  if((ftp->transfer == PPTRANSFER_INFO) && ftpc->file) {
    /* if a "head"-like request is being made (on a file) */

    /* we know ftpc->file is a valid pointer to a filename */
    result = Curl_pp_sendf(data, &ftpc->pp, "SIZE %s", ftpc->file);
    if(!result)
      ftp_state(data, FTP_SIZE);
  }
  else
    result = ftp_state_rest(data, conn);

  return result;
}

static CURLcode ftp_state_list(struct Curl_easy *data)
{
  CURLcode result = CURLE_OK;
  struct FTP *ftp = data->req.p.ftp;
  struct connectdata *conn = data->conn;

  /* If this output is to be machine-parsed, the NLST command might be better
     to use, since the LIST command output is not specified or standard in any
     way. It has turned out that the NLST list output is not the same on all
     servers either... */

  /*
     if FTPFILE_NOCWD was specified, we should add the path
     as argument for the LIST / NLST / or custom command.
     Whether the server will support this, is uncertain.

     The other ftp_filemethods will CWD into dir/dir/ first and
     then just do LIST (in that case: nothing to do here)
  */
  char *lstArg = NULL;
  char *cmd;

  if((data->set.ftp_filemethod == FTPFILE_NOCWD) && ftp->path) {
    /* url-decode before evaluation: e.g. paths starting/ending with %2f */
    const char *slashPos = NULL;
    char *rawPath = NULL;
    result = Curl_urldecode(ftp->path, 0, &rawPath, NULL, REJECT_CTRL);
    if(result)
      return result;

    slashPos = strrchr(rawPath, '/');
    if(slashPos) {
      /* chop off the file part if format is dir/file otherwise remove
         the trailing slash for dir/dir/ except for absolute path / */
      size_t n = slashPos - rawPath;
      if(n == 0)
        ++n;

      lstArg = rawPath;
      lstArg[n] = '\0';
    }
    else
      free(rawPath);
  }

  cmd = aprintf("%s%s%s",
                data->set.str[STRING_CUSTOMREQUEST] ?
                data->set.str[STRING_CUSTOMREQUEST] :
                (data->state.list_only ? "NLST" : "LIST"),
                lstArg ? " " : "",
                lstArg ? lstArg : "");
  free(lstArg);

  if(!cmd)
    return CURLE_OUT_OF_MEMORY;

  result = Curl_pp_sendf(data, &conn->proto.ftpc.pp, "%s", cmd);
  free(cmd);

  if(!result)
    ftp_state(data, FTP_LIST);

  return result;
}

static CURLcode ftp_state_retr_prequote(struct Curl_easy *data)
{
  /* We have sent the TYPE, now we must send the list of prequote strings */
  return ftp_state_quote(data, TRUE, FTP_RETR_PREQUOTE);
}

static CURLcode ftp_state_stor_prequote(struct Curl_easy *data)
{
  /* We have sent the TYPE, now we must send the list of prequote strings */
  return ftp_state_quote(data, TRUE, FTP_STOR_PREQUOTE);
}

static CURLcode ftp_state_type(struct Curl_easy *data)
{
  CURLcode result = CURLE_OK;
  struct FTP *ftp = data->req.p.ftp;
  struct connectdata *conn = data->conn;
  struct ftp_conn *ftpc = &conn->proto.ftpc;

  /* If we have selected NOBODY and HEADER, it means that we only want file
     information. Which in FTP cannot be much more than the file size and
     date. */
  if(data->req.no_body && ftpc->file &&
     ftp_need_type(conn, data->state.prefer_ascii)) {
    /* The SIZE command is _not_ RFC 959 specified, and therefore many servers
       may not support it! It is however the only way we have to get a file's
       size! */

    ftp->transfer = PPTRANSFER_INFO;
    /* this means no actual transfer will be made */

    /* Some servers return different sizes for different modes, and thus we
       must set the proper type before we check the size */
    result = ftp_nb_type(data, conn, data->state.prefer_ascii, FTP_TYPE);
    if(result)
      return result;
  }
  else
    result = ftp_state_size(data, conn);

  return result;
}

/* This is called after the CWD commands have been done in the beginning of
   the DO phase */
static CURLcode ftp_state_mdtm(struct Curl_easy *data)
{
  CURLcode result = CURLE_OK;
  struct connectdata *conn = data->conn;
  struct ftp_conn *ftpc = &conn->proto.ftpc;

  /* Requested time of file or time-depended transfer? */
  if((data->set.get_filetime || data->set.timecondition) && ftpc->file) {

    /* we have requested to get the modified-time of the file, this is a white
       spot as the MDTM is not mentioned in RFC959 */
    result = Curl_pp_sendf(data, &ftpc->pp, "MDTM %s", ftpc->file);

    if(!result)
      ftp_state(data, FTP_MDTM);
  }
  else
    result = ftp_state_type(data);

  return result;
}


/* This is called after the TYPE and possible quote commands have been sent */
static CURLcode ftp_state_ul_setup(struct Curl_easy *data,
                                   bool sizechecked)
{
  CURLcode result = CURLE_OK;
  struct connectdata *conn = data->conn;
  struct FTP *ftp = data->req.p.ftp;
  struct ftp_conn *ftpc = &conn->proto.ftpc;
  bool append = data->set.remote_append;

  if((data->state.resume_from && !sizechecked) ||
     ((data->state.resume_from > 0) && sizechecked)) {
    /* we are about to continue the uploading of a file */
    /* 1. get already existing file's size. We use the SIZE command for this
       which may not exist in the server!  The SIZE command is not in
       RFC959. */

    /* 2. This used to set REST. But since we can do append, we
       do not another ftp command. We just skip the source file
       offset and then we APPEND the rest on the file instead */

    /* 3. pass file-size number of bytes in the source file */
    /* 4. lower the infilesize counter */
    /* => transfer as usual */
    int seekerr = CURL_SEEKFUNC_OK;

    if(data->state.resume_from < 0) {
      /* Got no given size to start from, figure it out */
      result = Curl_pp_sendf(data, &ftpc->pp, "SIZE %s", ftpc->file);
      if(!result)
        ftp_state(data, FTP_STOR_SIZE);
      return result;
    }

    /* enable append */
    append = TRUE;

    /* Let's read off the proper amount of bytes from the input. */
    if(data->set.seek_func) {
      Curl_set_in_callback(data, TRUE);
      seekerr = data->set.seek_func(data->set.seek_client,
                                    data->state.resume_from, SEEK_SET);
      Curl_set_in_callback(data, FALSE);
    }

    if(seekerr != CURL_SEEKFUNC_OK) {
      curl_off_t passed = 0;
      if(seekerr != CURL_SEEKFUNC_CANTSEEK) {
        failf(data, "Could not seek stream");
        return CURLE_FTP_COULDNT_USE_REST;
      }
      /* seekerr == CURL_SEEKFUNC_CANTSEEK (cannot seek to offset) */
      do {
        char scratch[4*1024];
        size_t readthisamountnow =
          (data->state.resume_from - passed > (curl_off_t)sizeof(scratch)) ?
          sizeof(scratch) :
          curlx_sotouz(data->state.resume_from - passed);

        size_t actuallyread =
          data->state.fread_func(scratch, 1, readthisamountnow,
                                 data->state.in);

        passed += actuallyread;
        if((actuallyread == 0) || (actuallyread > readthisamountnow)) {
          /* this checks for greater-than only to make sure that the
             CURL_READFUNC_ABORT return code still aborts */
          failf(data, "Failed to read data");
          return CURLE_FTP_COULDNT_USE_REST;
        }
      } while(passed < data->state.resume_from);
    }
    /* now, decrease the size of the read */
    if(data->state.infilesize > 0) {
      data->state.infilesize -= data->state.resume_from;

      if(data->state.infilesize <= 0) {
        infof(data, "File already completely uploaded");

        /* no data to transfer */
        Curl_xfer_setup_nop(data);

        /* Set ->transfer so that we will not get any error in
         * ftp_done() because we did not transfer anything! */
        ftp->transfer = PPTRANSFER_NONE;

        ftp_state(data, FTP_STOP);
        return CURLE_OK;
      }
    }
    /* we have passed, proceed as normal */
  } /* resume_from */

  result = Curl_pp_sendf(data, &ftpc->pp, append ? "APPE %s" : "STOR %s",
                         ftpc->file);
  if(!result)
    ftp_state(data, FTP_STOR);

  return result;
}

static CURLcode ftp_state_quote(struct Curl_easy *data,
                                bool init,
                                ftpstate instate)
{
  CURLcode result = CURLE_OK;
  struct FTP *ftp = data->req.p.ftp;
  struct connectdata *conn = data->conn;
  struct ftp_conn *ftpc = &conn->proto.ftpc;
  bool quote = FALSE;
  struct curl_slist *item;

  switch(instate) {
  case FTP_QUOTE:
  default:
    item = data->set.quote;
    break;
  case FTP_RETR_PREQUOTE:
  case FTP_STOR_PREQUOTE:
    item = data->set.prequote;
    break;
  case FTP_POSTQUOTE:
    item = data->set.postquote;
    break;
  }

  /*
   * This state uses:
   * 'count1' to iterate over the commands to send
   * 'count2' to store whether to allow commands to fail
   */

  if(init)
    ftpc->count1 = 0;
  else
    ftpc->count1++;

  if(item) {
    int i = 0;

    /* Skip count1 items in the linked list */
    while((i < ftpc->count1) && item) {
      item = item->next;
      i++;
    }
    if(item) {
      char *cmd = item->data;
      if(cmd[0] == '*') {
        cmd++;
        ftpc->count2 = 1; /* the sent command is allowed to fail */
      }
      else
        ftpc->count2 = 0; /* failure means cancel operation */

      result = Curl_pp_sendf(data, &ftpc->pp, "%s", cmd);
      if(result)
        return result;
      ftp_state(data, instate);
      quote = TRUE;
    }
  }

  if(!quote) {
    /* No more quote to send, continue to ... */
    switch(instate) {
    case FTP_QUOTE:
    default:
      result = ftp_state_cwd(data, conn);
      break;
    case FTP_RETR_PREQUOTE:
      if(ftp->transfer != PPTRANSFER_BODY)
        ftp_state(data, FTP_STOP);
      else {
        if(ftpc->known_filesize != -1) {
          Curl_pgrsSetDownloadSize(data, ftpc->known_filesize);
          result = ftp_state_retr(data, ftpc->known_filesize);
        }
        else {
          if(data->set.ignorecl || data->state.prefer_ascii) {
            /* 'ignorecl' is used to support download of growing files. It
               prevents the state machine from requesting the file size from
               the server. With an unknown file size the download continues
               until the server terminates it, otherwise the client stops if
               the received byte count exceeds the reported file size. Set
               option CURLOPT_IGNORE_CONTENT_LENGTH to 1 to enable this
               behavior.

               In addition: asking for the size for 'TYPE A' transfers is not
               constructive since servers do not report the converted size. So
               skip it.
            */
            result = Curl_pp_sendf(data, &ftpc->pp, "RETR %s", ftpc->file);
            if(!result)
              ftp_state(data, FTP_RETR);
          }
          else {
            result = Curl_pp_sendf(data, &ftpc->pp, "SIZE %s", ftpc->file);
            if(!result)
              ftp_state(data, FTP_RETR_SIZE);
          }
        }
      }
      break;
    case FTP_STOR_PREQUOTE:
      result = ftp_state_ul_setup(data, FALSE);
      break;
    case FTP_POSTQUOTE:
      break;
    }
  }

  return result;
}

/* called from ftp_state_pasv_resp to switch to PASV in case of EPSV
   problems */
static CURLcode ftp_epsv_disable(struct Curl_easy *data,
                                 struct connectdata *conn)
{
  CURLcode result = CURLE_OK;

  if(conn->bits.ipv6
#ifndef CURL_DISABLE_PROXY
     && !(conn->bits.tunnel_proxy || conn->bits.socksproxy)
#endif
    ) {
    /* We cannot disable EPSV when doing IPv6, so this is instead a fail */
    failf(data, "Failed EPSV attempt, exiting");
    return CURLE_WEIRD_SERVER_REPLY;
  }

  infof(data, "Failed EPSV attempt. Disabling EPSV");
  /* disable it for next transfer */
  conn->bits.ftp_use_epsv = FALSE;
  Curl_conn_close(data, SECONDARYSOCKET);
  Curl_conn_cf_discard_all(data, conn, SECONDARYSOCKET);
  data->state.errorbuf = FALSE; /* allow error message to get
                                         rewritten */
  result = Curl_pp_sendf(data, &conn->proto.ftpc.pp, "%s", "PASV");
  if(!result) {
    conn->proto.ftpc.count1++;
    /* remain in/go to the FTP_PASV state */
    ftp_state(data, FTP_PASV);
  }
  return result;
}


static char *control_address(struct connectdata *conn)
{
  /* Returns the control connection IP address.
     If a proxy tunnel is used, returns the original hostname instead, because
     the effective control connection address is the proxy address,
     not the ftp host. */
#ifndef CURL_DISABLE_PROXY
  if(conn->bits.tunnel_proxy || conn->bits.socksproxy)
    return conn->host.name;
#endif
  return conn->primary.remote_ip;
}

static bool match_pasv_6nums(const char *p,
                             unsigned int *array) /* 6 numbers */
{
  int i;
  for(i = 0; i < 6; i++) {
    curl_off_t num;
    if(i) {
      if(*p != ',')
        return FALSE;
      p++;
    }
    if(Curl_str_number(&p, &num, 0xff))
      return FALSE;
    array[i] = (unsigned int)num;
  }
  return TRUE;
}

static CURLcode ftp_state_pasv_resp(struct Curl_easy *data,
                                    int ftpcode)
{
  struct connectdata *conn = data->conn;
  struct ftp_conn *ftpc = &conn->proto.ftpc;
  CURLcode result;
  struct Curl_dns_entry *addr = NULL;
  enum resolve_t rc;
  unsigned short connectport; /* the local port connect() should use! */
  struct pingpong *pp = &ftpc->pp;
  char *str =
    Curl_dyn_ptr(&pp->recvbuf) + 4; /* start on the first letter */

  /* if we come here again, make sure the former name is cleared */
  Curl_safefree(ftpc->newhost);

  if((ftpc->count1 == 0) &&
     (ftpcode == 229)) {
    /* positive EPSV response */
    char *ptr = strchr(str, '(');
    if(ptr) {
      char sep;
      ptr++;
      /* |||12345| */
      sep = ptr[0];
      if((ptr[1] == sep) && (ptr[2] == sep) && ISDIGIT(ptr[3])) {
        const char *p = &ptr[3];
        curl_off_t num;
        if(Curl_str_number(&p, &num, 0xffff) || (*p != sep)) {
          failf(data, "Illegal port number in EPSV reply");
          return CURLE_FTP_WEIRD_PASV_REPLY;
        }
        ftpc->newport = (unsigned short)num;
        ftpc->newhost = strdup(control_address(conn));
        if(!ftpc->newhost)
          return CURLE_OUT_OF_MEMORY;
      }
      else
        ptr = NULL;
    }
    if(!ptr) {
      failf(data, "Weirdly formatted EPSV reply");
      return CURLE_FTP_WEIRD_PASV_REPLY;
    }
  }
  else if((ftpc->count1 == 1) &&
          (ftpcode == 227)) {
    /* positive PASV response */
    unsigned int ip[6];

    /*
     * Scan for a sequence of six comma-separated numbers and use them as
     * IP+port indicators.
     *
     * Found reply-strings include:
     * "227 Entering Passive Mode (127,0,0,1,4,51)"
     * "227 Data transfer will passively listen to 127,0,0,1,4,51"
     * "227 Entering passive mode. 127,0,0,1,4,51"
     */
    while(*str) {
      if(match_pasv_6nums(str, ip))
        break;
      str++;
    }

    if(!*str) {
      failf(data, "Couldn't interpret the 227-response");
      return CURLE_FTP_WEIRD_227_FORMAT;
    }

    /* we got OK from server */
    if(data->set.ftp_skip_ip) {
      /* told to ignore the remotely given IP but instead use the host we used
         for the control connection */
      infof(data, "Skip %u.%u.%u.%u for data connection, reuse %s instead",
            ip[0], ip[1], ip[2], ip[3],
            conn->host.name);
      ftpc->newhost = strdup(control_address(conn));
    }
    else
      ftpc->newhost = aprintf("%u.%u.%u.%u", ip[0], ip[1], ip[2], ip[3]);

    if(!ftpc->newhost)
      return CURLE_OUT_OF_MEMORY;

    ftpc->newport = (unsigned short)(((ip[4] << 8) + ip[5]) & 0xffff);
  }
  else if(ftpc->count1 == 0) {
    /* EPSV failed, move on to PASV */
    return ftp_epsv_disable(data, conn);
  }
  else {
    failf(data, "Bad PASV/EPSV response: %03d", ftpcode);
    return CURLE_FTP_WEIRD_PASV_REPLY;
  }

#ifndef CURL_DISABLE_PROXY
  if(conn->bits.proxy) {
    /*
     * This connection uses a proxy and we need to connect to the proxy again
     * here. We do not want to rely on a former host lookup that might've
     * expired now, instead we remake the lookup here and now!
     */
    const char * const host_name = conn->bits.socksproxy ?
      conn->socks_proxy.host.name : conn->http_proxy.host.name;
    rc = Curl_resolv(data, host_name, conn->primary.remote_port, FALSE, &addr);
    if(rc == CURLRESOLV_PENDING)
      /* BLOCKING, ignores the return code but 'addr' will be NULL in
         case of failure */
      (void)Curl_resolver_wait_resolv(data, &addr);

    /* we connect to the proxy's port */
    connectport = (unsigned short)conn->primary.remote_port;

    if(!addr) {
      failf(data, "cannot resolve proxy host %s:%hu", host_name, connectport);
      return CURLE_COULDNT_RESOLVE_PROXY;
    }
  }
  else
#endif
  {
    /* normal, direct, ftp connection */
    DEBUGASSERT(ftpc->newhost);

    /* postponed address resolution in case of tcp fastopen */
    if(conn->bits.tcp_fastopen && !conn->bits.reuse && !ftpc->newhost[0]) {
      Curl_safefree(ftpc->newhost);
      ftpc->newhost = strdup(control_address(conn));
      if(!ftpc->newhost)
        return CURLE_OUT_OF_MEMORY;
    }

    rc = Curl_resolv(data, ftpc->newhost, ftpc->newport, FALSE, &addr);
    if(rc == CURLRESOLV_PENDING)
      /* BLOCKING */
      (void)Curl_resolver_wait_resolv(data, &addr);

    connectport = ftpc->newport; /* we connect to the remote port */

    if(!addr) {
      failf(data, "cannot resolve new host %s:%hu",
            ftpc->newhost, connectport);
      return CURLE_FTP_CANT_GET_HOST;
    }
  }

  result = Curl_conn_setup(data, conn, SECONDARYSOCKET, addr,
                           conn->bits.ftp_use_data_ssl ?
                           CURL_CF_SSL_ENABLE : CURL_CF_SSL_DISABLE);

  if(result) {
    Curl_resolv_unlink(data, &addr); /* we are done using this address */
    if(ftpc->count1 == 0 && ftpcode == 229)
      return ftp_epsv_disable(data, conn);

    return result;
  }


  /*
   * When this is used from the multi interface, this might've returned with
   * the 'connected' set to FALSE and thus we are now awaiting a non-blocking
   * connect to connect.
   */

  if(data->set.verbose)
    /* this just dumps information about this second connection */
    ftp_pasv_verbose(data, addr->addr, ftpc->newhost, connectport);

  Curl_resolv_unlink(data, &addr); /* we are done using this address */

  Curl_safefree(conn->secondaryhostname);
  conn->secondary_port = ftpc->newport;
  conn->secondaryhostname = strdup(ftpc->newhost);
  if(!conn->secondaryhostname)
    return CURLE_OUT_OF_MEMORY;

  conn->bits.do_more = TRUE;
  ftp_state(data, FTP_STOP); /* this phase is completed */

  return result;
}

static CURLcode ftp_state_port_resp(struct Curl_easy *data,
                                    int ftpcode)
{
  struct connectdata *conn = data->conn;
  struct ftp_conn *ftpc = &conn->proto.ftpc;
  ftpport fcmd = (ftpport)ftpc->count1;
  CURLcode result = CURLE_OK;

  /* The FTP spec tells a positive response should have code 200.
     Be more permissive here to tolerate deviant servers. */
  if(ftpcode / 100 != 2) {
    /* the command failed */

    if(EPRT == fcmd) {
      infof(data, "disabling EPRT usage");
      conn->bits.ftp_use_eprt = FALSE;
    }
    fcmd++;

    if(fcmd == DONE) {
      failf(data, "Failed to do PORT");
      result = CURLE_FTP_PORT_FAILED;
    }
    else
      /* try next */
      result = ftp_state_use_port(data, fcmd);
  }
  else {
    infof(data, "Connect data stream actively");
    ftp_state(data, FTP_STOP); /* end of DO phase */
    result = ftp_dophase_done(data, FALSE);
  }

  return result;
}

static int twodigit(const char *p)
{
  return (p[0]-'0') * 10 + (p[1]-'0');
}

static bool ftp_213_date(const char *p, int *year, int *month, int *day,
                         int *hour, int *minute, int *second)
{
  size_t len = strlen(p);
  if(len < 14)
    return FALSE;
  *year = twodigit(&p[0]) * 100 + twodigit(&p[2]);
  *month = twodigit(&p[4]);
  *day = twodigit(&p[6]);
  *hour = twodigit(&p[8]);
  *minute = twodigit(&p[10]);
  *second = twodigit(&p[12]);

  if((*month > 12) || (*day > 31) || (*hour > 23) || (*minute > 59) ||
     (*second > 60))
    return FALSE;
  return TRUE;
}

static CURLcode client_write_header(struct Curl_easy *data,
                                    char *buf, size_t blen)
{
  /* Some replies from an FTP server are written to the client
   * as CLIENTWRITE_HEADER, formatted as if they came from a
   * HTTP conversation.
   * In all protocols, CLIENTWRITE_HEADER data is only passed to
   * the body write callback when data->set.include_header is set
   * via CURLOPT_HEADER.
   * For historic reasons, FTP never played this game and expects
   * all its HEADERs to do that always. Set that flag during the
   * call to Curl_client_write() so it does the right thing.
   *
   * Notice that we cannot enable this flag for FTP in general,
   * as an FTP transfer might involve an HTTP proxy connection and
   * headers from CONNECT should not automatically be part of the
   * output. */
  CURLcode result;
  bool save = data->set.include_header;
  data->set.include_header = TRUE;
  result = Curl_client_write(data, CLIENTWRITE_HEADER, buf, blen);
  data->set.include_header = save;
  return result;
}

static CURLcode ftp_state_mdtm_resp(struct Curl_easy *data,
                                    int ftpcode)
{
  CURLcode result = CURLE_OK;
  struct FTP *ftp = data->req.p.ftp;
  struct connectdata *conn = data->conn;
  struct ftp_conn *ftpc = &conn->proto.ftpc;

  switch(ftpcode) {
  case 213:
    {
      /* we got a time. Format should be: "YYYYMMDDHHMMSS[.sss]" where the
         last .sss part is optional and means fractions of a second */
      int year, month, day, hour, minute, second;
      struct pingpong *pp = &ftpc->pp;
      char *resp = Curl_dyn_ptr(&pp->recvbuf) + 4;
      if(ftp_213_date(resp, &year, &month, &day, &hour, &minute, &second)) {
        /* we have a time, reformat it */
        char timebuf[24];
        msnprintf(timebuf, sizeof(timebuf),
                  "%04d%02d%02d %02d:%02d:%02d GMT",
                  year, month, day, hour, minute, second);
        /* now, convert this into a time() value: */
        data->info.filetime = Curl_getdate_capped(timebuf);
      }

#ifdef CURL_FTP_HTTPSTYLE_HEAD
      /* If we asked for a time of the file and we actually got one as well,
         we "emulate" an HTTP-style header in our output. */

#if defined(__GNUC__) && (defined(__DJGPP__) || defined(__AMIGA__))
#pragma GCC diagnostic push
/* 'time_t' is unsigned in MSDOS and AmigaOS. Silence:
   warning: comparison of unsigned expression in '>= 0' is always true */
#pragma GCC diagnostic ignored "-Wtype-limits"
#endif
      if(data->req.no_body &&
         ftpc->file &&
         data->set.get_filetime &&
         (data->info.filetime >= 0) ) {
#if defined(__GNUC__) && (defined(__DJGPP__) || defined(__AMIGA__))
#pragma GCC diagnostic pop
#endif
        char headerbuf[128];
        int headerbuflen;
        time_t filetime = data->info.filetime;
        struct tm buffer;
        const struct tm *tm = &buffer;

        result = Curl_gmtime(filetime, &buffer);
        if(result)
          return result;

        /* format: "Tue, 15 Nov 1994 12:45:26" */
        headerbuflen =
          msnprintf(headerbuf, sizeof(headerbuf),
                    "Last-Modified: %s, %02d %s %4d %02d:%02d:%02d GMT\r\n",
                    Curl_wkday[tm->tm_wday ? tm->tm_wday-1 : 6],
                    tm->tm_mday,
                    Curl_month[tm->tm_mon],
                    tm->tm_year + 1900,
                    tm->tm_hour,
                    tm->tm_min,
                    tm->tm_sec);
        result = client_write_header(data, headerbuf, headerbuflen);
        if(result)
          return result;
      } /* end of a ridiculous amount of conditionals */
#endif
    }
    break;
  default:
    infof(data, "unsupported MDTM reply format");
    break;
  case 550: /* 550 is used for several different problems, e.g.
               "No such file or directory" or "Permission denied".
               It does not mean that the file does not exist at all. */
    infof(data, "MDTM failed: file does not exist or permission problem,"
          " continuing");
    break;
  }

  if(data->set.timecondition) {
    if((data->info.filetime > 0) && (data->set.timevalue > 0)) {
      switch(data->set.timecondition) {
      case CURL_TIMECOND_IFMODSINCE:
      default:
        if(data->info.filetime <= data->set.timevalue) {
          infof(data, "The requested document is not new enough");
          ftp->transfer = PPTRANSFER_NONE; /* mark to not transfer data */
          data->info.timecond = TRUE;
          ftp_state(data, FTP_STOP);
          return CURLE_OK;
        }
        break;
      case CURL_TIMECOND_IFUNMODSINCE:
        if(data->info.filetime > data->set.timevalue) {
          infof(data, "The requested document is not old enough");
          ftp->transfer = PPTRANSFER_NONE; /* mark to not transfer data */
          data->info.timecond = TRUE;
          ftp_state(data, FTP_STOP);
          return CURLE_OK;
        }
        break;
      } /* switch */
    }
    else {
      infof(data, "Skipping time comparison");
    }
  }

  if(!result)
    result = ftp_state_type(data);

  return result;
}

static CURLcode ftp_state_type_resp(struct Curl_easy *data,
                                    int ftpcode,
                                    ftpstate instate)
{
  CURLcode result = CURLE_OK;
  struct connectdata *conn = data->conn;

  if(ftpcode/100 != 2) {
    /* "sasserftpd" and "(u)r(x)bot ftpd" both responds with 226 after a
       successful 'TYPE I'. While that is not as RFC959 says, it is still a
       positive response code and we allow that. */
    failf(data, "Couldn't set desired mode");
    return CURLE_FTP_COULDNT_SET_TYPE;
  }
  if(ftpcode != 200)
    infof(data, "Got a %03d response code instead of the assumed 200",
          ftpcode);

  if(instate == FTP_TYPE)
    result = ftp_state_size(data, conn);
  else if(instate == FTP_LIST_TYPE)
    result = ftp_state_list(data);
  else if(instate == FTP_RETR_TYPE)
    result = ftp_state_retr_prequote(data);
  else if(instate == FTP_STOR_TYPE)
    result = ftp_state_stor_prequote(data);

  return result;
}

static CURLcode ftp_state_retr(struct Curl_easy *data,
                               curl_off_t filesize)
{
  CURLcode result = CURLE_OK;
  struct FTP *ftp = data->req.p.ftp;
  struct connectdata *conn = data->conn;
  struct ftp_conn *ftpc = &conn->proto.ftpc;

  CURL_TRC_FTP(data, "[%s] ftp_state_retr()", FTP_DSTATE(data));
  if(data->set.max_filesize && (filesize > data->set.max_filesize)) {
    failf(data, "Maximum file size exceeded");
    return CURLE_FILESIZE_EXCEEDED;
  }
  ftp->downloadsize = filesize;

  if(data->state.resume_from) {
    /* We always (attempt to) get the size of downloads, so it is done before
       this even when not doing resumes. */
    if(filesize == -1) {
      infof(data, "ftp server does not support SIZE");
      /* We could not get the size and therefore we cannot know if there really
         is a part of the file left to get, although the server will just
         close the connection when we start the connection so it will not cause
         us any harm, just not make us exit as nicely. */
    }
    else {
      /* We got a file size report, so we check that there actually is a
         part of the file left to get, or else we go home.  */
      if(data->state.resume_from < 0) {
        /* We are supposed to download the last abs(from) bytes */
        if(filesize < -data->state.resume_from) {
          failf(data, "Offset (%" FMT_OFF_T
                ") was beyond file size (%" FMT_OFF_T ")",
                data->state.resume_from, filesize);
          return CURLE_BAD_DOWNLOAD_RESUME;
        }
        /* convert to size to download */
        ftp->downloadsize = -data->state.resume_from;
        /* download from where? */
        data->state.resume_from = filesize - ftp->downloadsize;
      }
      else {
        if(filesize < data->state.resume_from) {
          failf(data, "Offset (%" FMT_OFF_T
                ") was beyond file size (%" FMT_OFF_T ")",
                data->state.resume_from, filesize);
          return CURLE_BAD_DOWNLOAD_RESUME;
        }
        /* Now store the number of bytes we are expected to download */
        ftp->downloadsize = filesize-data->state.resume_from;
      }
    }

    if(ftp->downloadsize == 0) {
      /* no data to transfer */
      Curl_xfer_setup_nop(data);
      infof(data, "File already completely downloaded");

      /* Set ->transfer so that we will not get any error in ftp_done()
       * because we did not transfer the any file */
      ftp->transfer = PPTRANSFER_NONE;
      ftp_state(data, FTP_STOP);
      return CURLE_OK;
    }

    /* Set resume file transfer offset */
    infof(data, "Instructs server to resume from offset %" FMT_OFF_T,
          data->state.resume_from);

    result = Curl_pp_sendf(data, &ftpc->pp, "REST %" FMT_OFF_T,
                           data->state.resume_from);
    if(!result)
      ftp_state(data, FTP_RETR_REST);
  }
  else {
    /* no resume */
    result = Curl_pp_sendf(data, &ftpc->pp, "RETR %s", ftpc->file);
    if(!result)
      ftp_state(data, FTP_RETR);
  }

  return result;
}

static CURLcode ftp_state_size_resp(struct Curl_easy *data,
                                    int ftpcode,
                                    ftpstate instate)
{
  CURLcode result = CURLE_OK;
  curl_off_t filesize = -1;
  char *buf = Curl_dyn_ptr(&data->conn->proto.ftpc.pp.recvbuf);
  size_t len = data->conn->proto.ftpc.pp.nfinal;

  /* get the size from the ascii string: */
  if(ftpcode == 213) {
    /* To allow servers to prepend "rubbish" in the response string, we scan
       for all the digits at the end of the response and parse only those as a
       number. */
    char *start = &buf[4];
    const char *fdigit = memchr(start, '\r', len);
    if(fdigit) {
      fdigit--;
      if(*fdigit == '\n')
        fdigit--;
      while(ISDIGIT(fdigit[-1]) && (fdigit > start))
        fdigit--;
    }
    else
      fdigit = start;
    if(Curl_str_number(&fdigit, &filesize, CURL_OFF_T_MAX))
      filesize = -1; /* size remain unknown */
  }
  else if(ftpcode == 550) { /* "No such file or directory" */
    /* allow a SIZE failure for (resumed) uploads, when probing what command
       to use */
    if(instate != FTP_STOR_SIZE) {
      failf(data, "The file does not exist");
      return CURLE_REMOTE_FILE_NOT_FOUND;
    }
  }

  if(instate == FTP_SIZE) {
#ifdef CURL_FTP_HTTPSTYLE_HEAD
    if(-1 != filesize) {
      char clbuf[128];
      int clbuflen = msnprintf(clbuf, sizeof(clbuf),
                "Content-Length: %" FMT_OFF_T "\r\n", filesize);
      result = client_write_header(data, clbuf, clbuflen);
      if(result)
        return result;
    }
#endif
    Curl_pgrsSetDownloadSize(data, filesize);
    result = ftp_state_rest(data, data->conn);
  }
  else if(instate == FTP_RETR_SIZE) {
    Curl_pgrsSetDownloadSize(data, filesize);
    result = ftp_state_retr(data, filesize);
  }
  else if(instate == FTP_STOR_SIZE) {
    data->state.resume_from = filesize;
    result = ftp_state_ul_setup(data, TRUE);
  }

  return result;
}

static CURLcode ftp_state_rest_resp(struct Curl_easy *data,
                                    struct connectdata *conn,
                                    int ftpcode,
                                    ftpstate instate)
{
  CURLcode result = CURLE_OK;
  struct ftp_conn *ftpc = &conn->proto.ftpc;

  switch(instate) {
  case FTP_REST:
  default:
#ifdef CURL_FTP_HTTPSTYLE_HEAD
    if(ftpcode == 350) {
      char buffer[24]= { "Accept-ranges: bytes\r\n" };
      result = client_write_header(data, buffer, strlen(buffer));
      if(result)
        return result;
    }
#endif
    result = ftp_state_prepare_transfer(data);
    break;

  case FTP_RETR_REST:
    if(ftpcode != 350) {
      failf(data, "Couldn't use REST");
      result = CURLE_FTP_COULDNT_USE_REST;
    }
    else {
      result = Curl_pp_sendf(data, &ftpc->pp, "RETR %s", ftpc->file);
      if(!result)
        ftp_state(data, FTP_RETR);
    }
    break;
  }

  return result;
}

static CURLcode ftp_state_stor_resp(struct Curl_easy *data,
                                    int ftpcode, ftpstate instate)
{
  CURLcode result = CURLE_OK;
  struct connectdata *conn = data->conn;

  if(ftpcode >= 400) {
    failf(data, "Failed FTP upload: %0d", ftpcode);
    ftp_state(data, FTP_STOP);
    /* oops, we never close the sockets! */
    return CURLE_UPLOAD_FAILED;
  }

  conn->proto.ftpc.state_saved = instate;

  /* PORT means we are now awaiting the server to connect to us. */
  if(data->set.ftp_use_port) {
    struct ftp_conn *ftpc = &conn->proto.ftpc;
    bool connected;

    ftp_state(data, FTP_STOP); /* no longer in STOR state */

    result = Curl_conn_connect(data, SECONDARYSOCKET, FALSE, &connected);
    if(result)
      return result;

    if(!connected) {
      infof(data, "Data conn was not available immediately");
      ftpc->wait_data_conn = TRUE;
      return ftp_check_ctrl_on_data_wait(data);
    }
    ftpc->wait_data_conn = FALSE;
  }
  return InitiateTransfer(data);
}

/* for LIST and RETR responses */
static CURLcode ftp_state_get_resp(struct Curl_easy *data,
                                   int ftpcode,
                                   ftpstate instate)
{
  CURLcode result = CURLE_OK;
  struct FTP *ftp = data->req.p.ftp;
  struct connectdata *conn = data->conn;

  if((ftpcode == 150) || (ftpcode == 125)) {

    /*
      A;
      150 Opening BINARY mode data connection for /etc/passwd (2241
      bytes).  (ok, the file is being transferred)

      B:
      150 Opening ASCII mode data connection for /bin/ls

      C:
      150 ASCII data connection for /bin/ls (137.167.104.91,37445) (0 bytes).

      D:
      150 Opening ASCII mode data connection for [file] (0.0.0.0,0) (545 bytes)

      E:
      125 Data connection already open; Transfer starting. */

    curl_off_t size = -1; /* default unknown size */


    /*
     * It appears that there are FTP-servers that return size 0 for files when
     * SIZE is used on the file while being in BINARY mode. To work around
     * that (stupid) behavior, we attempt to parse the RETR response even if
     * the SIZE returned size zero.
     *
     * Debugging help from Salvatore Sorrentino on February 26, 2003.
     */

    if((instate != FTP_LIST) &&
       !data->state.prefer_ascii &&
       !data->set.ignorecl &&
       (ftp->downloadsize < 1)) {
      /*
       * It seems directory listings either do not show the size or often uses
       * size 0 anyway. ASCII transfers may cause that the transferred amount
       * of data is not the same as this line tells, why using this number in
       * those cases only confuses us.
       *
       * Example D above makes this parsing a little tricky */
      const char *bytes;
      char *buf = Curl_dyn_ptr(&conn->proto.ftpc.pp.recvbuf);
      bytes = strstr(buf, " bytes");
      if(bytes) {
        long in = (long)(--bytes-buf);
        /* this is a hint there is size information in there! ;-) */
        while(--in) {
          /* scan for the left parenthesis and break there */
          if('(' == *bytes)
            break;
          /* skip only digits */
          if(!ISDIGIT(*bytes)) {
            bytes = NULL;
            break;
          }
          /* one more estep backwards */
          bytes--;
        }
        /* if we have nothing but digits: */
        if(bytes) {
          ++bytes;
          /* get the number! */
          if(Curl_str_number(&bytes, &size, CURL_OFF_T_MAX))
            size = 1;
        }
      }
    }
    else if(ftp->downloadsize > -1)
      size = ftp->downloadsize;

    if(size > data->req.maxdownload && data->req.maxdownload > 0)
      size = data->req.size = data->req.maxdownload;
    else if((instate != FTP_LIST) && (data->state.prefer_ascii))
      size = -1; /* kludge for servers that understate ASCII mode file size */

    infof(data, "Maxdownload = %" FMT_OFF_T, data->req.maxdownload);

    if(instate != FTP_LIST)
      infof(data, "Getting file with size: %" FMT_OFF_T, size);

    /* FTP download: */
    conn->proto.ftpc.state_saved = instate;
    conn->proto.ftpc.retr_size_saved = size;

    if(data->set.ftp_use_port) {
      struct ftp_conn *ftpc = &conn->proto.ftpc;
      bool connected;

      result = Curl_conn_connect(data, SECONDARYSOCKET, FALSE, &connected);
      if(result)
        return result;

      if(!connected) {
        infof(data, "Data conn was not available immediately");
        ftp_state(data, FTP_STOP);
        ftpc->wait_data_conn = TRUE;
        return ftp_check_ctrl_on_data_wait(data);
      }
      ftpc->wait_data_conn = FALSE;
    }
    return InitiateTransfer(data);
  }
  else {
    if((instate == FTP_LIST) && (ftpcode == 450)) {
      /* simply no matching files in the dir listing */
      ftp->transfer = PPTRANSFER_NONE; /* do not download anything */
      ftp_state(data, FTP_STOP); /* this phase is over */
    }
    else {
      failf(data, "RETR response: %03d", ftpcode);
      return instate == FTP_RETR && ftpcode == 550 ?
        CURLE_REMOTE_FILE_NOT_FOUND :
        CURLE_FTP_COULDNT_RETR_FILE;
    }
  }

  return result;
}

/* after USER, PASS and ACCT */
static CURLcode ftp_state_loggedin(struct Curl_easy *data)
{
  CURLcode result = CURLE_OK;
  struct connectdata *conn = data->conn;

  if(conn->bits.ftp_use_control_ssl) {
    /* PBSZ = PROTECTION BUFFER SIZE.

    The 'draft-murray-auth-ftp-ssl' (draft 12, page 7) says:

    Specifically, the PROT command MUST be preceded by a PBSZ
    command and a PBSZ command MUST be preceded by a successful
    security data exchange (the TLS negotiation in this case)

    ... (and on page 8):

    Thus the PBSZ command must still be issued, but must have a
    parameter of '0' to indicate that no buffering is taking place
    and the data connection should not be encapsulated.
    */
    result = Curl_pp_sendf(data, &conn->proto.ftpc.pp, "PBSZ %d", 0);
    if(!result)
      ftp_state(data, FTP_PBSZ);
  }
  else {
    result = ftp_state_pwd(data, conn);
  }
  return result;
}

/* for USER and PASS responses */
static CURLcode ftp_state_user_resp(struct Curl_easy *data,
                                    int ftpcode)
{
  CURLcode result = CURLE_OK;
  struct connectdata *conn = data->conn;
  struct ftp_conn *ftpc = &conn->proto.ftpc;

  /* some need password anyway, and others just return 2xx ignored */
  if((ftpcode == 331) && (ftpc->state == FTP_USER)) {
    /* 331 Password required for ...
       (the server requires to send the user's password too) */
    result = Curl_pp_sendf(data, &ftpc->pp, "PASS %s",
                           conn->passwd ? conn->passwd : "");
    if(!result)
      ftp_state(data, FTP_PASS);
  }
  else if(ftpcode/100 == 2) {
    /* 230 User ... logged in.
       (the user logged in with or without password) */
    result = ftp_state_loggedin(data);
  }
  else if(ftpcode == 332) {
    if(data->set.str[STRING_FTP_ACCOUNT]) {
      result = Curl_pp_sendf(data, &ftpc->pp, "ACCT %s",
                             data->set.str[STRING_FTP_ACCOUNT]);
      if(!result)
        ftp_state(data, FTP_ACCT);
    }
    else {
      failf(data, "ACCT requested but none available");
      result = CURLE_LOGIN_DENIED;
    }
  }
  else {
    /* All other response codes, like:

    530 User ... access denied
    (the server denies to log the specified user) */

    if(data->set.str[STRING_FTP_ALTERNATIVE_TO_USER] &&
       !ftpc->ftp_trying_alternative) {
      /* Ok, USER failed. Let's try the supplied command. */
      result =
        Curl_pp_sendf(data, &ftpc->pp, "%s",
                      data->set.str[STRING_FTP_ALTERNATIVE_TO_USER]);
      if(!result) {
        ftpc->ftp_trying_alternative = TRUE;
        ftp_state(data, FTP_USER);
      }
    }
    else {
      failf(data, "Access denied: %03d", ftpcode);
      result = CURLE_LOGIN_DENIED;
    }
  }
  return result;
}

/* for ACCT response */
static CURLcode ftp_state_acct_resp(struct Curl_easy *data,
                                    int ftpcode)
{
  CURLcode result = CURLE_OK;
  if(ftpcode != 230) {
    failf(data, "ACCT rejected by server: %03d", ftpcode);
    result = CURLE_FTP_WEIRD_PASS_REPLY; /* FIX */
  }
  else
    result = ftp_state_loggedin(data);

  return result;
}


static CURLcode ftp_statemachine(struct Curl_easy *data,
                                 struct connectdata *conn)
{
  CURLcode result;
  int ftpcode;
  struct ftp_conn *ftpc = &conn->proto.ftpc;
  struct pingpong *pp = &ftpc->pp;
  static const char * const ftpauth[] = { "SSL", "TLS" };
  size_t nread = 0;

  if(pp->sendleft)
    return Curl_pp_flushsend(data, pp);

  result = ftp_readresp(data, FIRSTSOCKET, pp, &ftpcode, &nread);
  if(result)
    return result;

  if(ftpcode) {
    /* we have now received a full FTP server response */
    switch(ftpc->state) {
    case FTP_WAIT220:
      if(ftpcode == 230) {
        /* 230 User logged in - already! Take as 220 if TLS required. */
        if(data->set.use_ssl <= CURLUSESSL_TRY ||
           conn->bits.ftp_use_control_ssl)
          return ftp_state_user_resp(data, ftpcode);
      }
      else if(ftpcode != 220) {
        failf(data, "Got a %03d ftp-server response when 220 was expected",
              ftpcode);
        return CURLE_WEIRD_SERVER_REPLY;
      }

      /* We have received a 220 response fine, now we proceed. */
#ifdef HAVE_GSSAPI
      if(data->set.krb) {
        /* If not anonymous login, try a secure login. Note that this
           procedure is still BLOCKING. */

        Curl_sec_request_prot(conn, "private");
        /* We set private first as default, in case the line below fails to
           set a valid level */
        Curl_sec_request_prot(conn, data->set.str[STRING_KRB_LEVEL]);

        if(Curl_sec_login(data, conn)) {
          failf(data, "secure login failed");
          return CURLE_WEIRD_SERVER_REPLY;
        }
        infof(data, "Authentication successful");
      }
#endif

      if(data->set.use_ssl && !conn->bits.ftp_use_control_ssl) {
        /* We do not have a SSL/TLS control connection yet, but FTPS is
           requested. Try a FTPS connection now */

        ftpc->count3 = 0;
        switch(data->set.ftpsslauth) {
        case CURLFTPAUTH_DEFAULT:
        case CURLFTPAUTH_SSL:
          ftpc->count2 = 1; /* add one to get next */
          ftpc->count1 = 0;
          break;
        case CURLFTPAUTH_TLS:
          ftpc->count2 = -1; /* subtract one to get next */
          ftpc->count1 = 1;
          break;
        default:
          failf(data, "unsupported parameter to CURLOPT_FTPSSLAUTH: %d",
                (int)data->set.ftpsslauth);
          return CURLE_UNKNOWN_OPTION; /* we do not know what to do */
        }
        result = Curl_pp_sendf(data, &ftpc->pp, "AUTH %s",
                               ftpauth[ftpc->count1]);
        if(!result)
          ftp_state(data, FTP_AUTH);
      }
      else
        result = ftp_state_user(data, conn);
      break;

    case FTP_AUTH:
      /* we have gotten the response to a previous AUTH command */

      if(pp->overflow)
        return CURLE_WEIRD_SERVER_REPLY; /* Forbid pipelining in response. */

      /* RFC2228 (page 5) says:
       *
       * If the server is willing to accept the named security mechanism,
       * and does not require any security data, it must respond with
       * reply code 234/334.
       */

      if((ftpcode == 234) || (ftpcode == 334)) {
        /* this was BLOCKING, keep it so for now */
        bool done;
        if(!Curl_conn_is_ssl(conn, FIRSTSOCKET)) {
          result = Curl_ssl_cfilter_add(data, conn, FIRSTSOCKET);
          if(result) {
            /* we failed and bail out */
            return CURLE_USE_SSL_FAILED;
          }
        }
        result = Curl_conn_connect(data, FIRSTSOCKET, TRUE, &done);
        if(!result) {
          conn->bits.ftp_use_data_ssl = FALSE; /* clear-text data */
          conn->bits.ftp_use_control_ssl = TRUE; /* SSL on control */
          result = ftp_state_user(data, conn);
        }
      }
      else if(ftpc->count3 < 1) {
        ftpc->count3++;
        ftpc->count1 += ftpc->count2; /* get next attempt */
        result = Curl_pp_sendf(data, &ftpc->pp, "AUTH %s",
                               ftpauth[ftpc->count1]);
        /* remain in this same state */
      }
      else {
        if(data->set.use_ssl > CURLUSESSL_TRY)
          /* we failed and CURLUSESSL_CONTROL or CURLUSESSL_ALL is set */
          result = CURLE_USE_SSL_FAILED;
        else
          /* ignore the failure and continue */
          result = ftp_state_user(data, conn);
      }
      break;

    case FTP_USER:
    case FTP_PASS:
      result = ftp_state_user_resp(data, ftpcode);
      break;

    case FTP_ACCT:
      result = ftp_state_acct_resp(data, ftpcode);
      break;

    case FTP_PBSZ:
      result =
        Curl_pp_sendf(data, &ftpc->pp, "PROT %c",
                      data->set.use_ssl == CURLUSESSL_CONTROL ? 'C' : 'P');
      if(!result)
        ftp_state(data, FTP_PROT);
      break;

    case FTP_PROT:
      if(ftpcode/100 == 2)
        /* We have enabled SSL for the data connection! */
        conn->bits.ftp_use_data_ssl =
          (data->set.use_ssl != CURLUSESSL_CONTROL);
      /* FTP servers typically responds with 500 if they decide to reject
         our 'P' request */
      else if(data->set.use_ssl > CURLUSESSL_CONTROL)
        /* we failed and bails out */
        return CURLE_USE_SSL_FAILED;

      if(data->set.ftp_ccc) {
        /* CCC - Clear Command Channel
         */
        result = Curl_pp_sendf(data, &ftpc->pp, "%s", "CCC");
        if(!result)
          ftp_state(data, FTP_CCC);
      }
      else
        result = ftp_state_pwd(data, conn);
      break;

    case FTP_CCC:
      if(ftpcode < 500) {
        /* First shut down the SSL layer (note: this call will block) */
        /* This has only been tested on the proftpd server, and the mod_tls
         * code sends a close notify alert without waiting for a close notify
         * alert in response. Thus we wait for a close notify alert from the
         * server, but we do not send one. Let's hope other servers do
         * the same... */
        result = Curl_ssl_cfilter_remove(data, FIRSTSOCKET,
          (data->set.ftp_ccc == CURLFTPSSL_CCC_ACTIVE));

        if(result)
          failf(data, "Failed to clear the command channel (CCC)");
      }
      if(!result)
        /* Then continue as normal */
        result = ftp_state_pwd(data, conn);
      break;

    case FTP_PWD:
      if(ftpcode == 257) {
        char *ptr = Curl_dyn_ptr(&pp->recvbuf) + 4; /* start on the first
                                                       letter */
        bool entry_extracted = FALSE;
        struct dynbuf out;
        Curl_dyn_init(&out, 1000);

        /* Reply format is like
           257<space>[rubbish]"<directory-name>"<space><commentary> and the
           RFC959 says

           The directory name can contain any character; embedded
           double-quotes should be escaped by double-quotes (the
           "quote-doubling" convention).
        */

        /* scan for the first double-quote for non-standard responses */
        while(*ptr != '\n' && *ptr != '\0' && *ptr != '"')
          ptr++;

        if('\"' == *ptr) {
          /* it started good */
          for(ptr++; *ptr; ptr++) {
            if('\"' == *ptr) {
              if('\"' == ptr[1]) {
                /* "quote-doubling" */
                result = Curl_dyn_addn(&out, &ptr[1], 1);
                ptr++;
              }
              else {
                /* end of path */
                if(Curl_dyn_len(&out))
                  entry_extracted = TRUE;
                break; /* get out of this loop */
              }
            }
            else
              result = Curl_dyn_addn(&out, ptr, 1);
            if(result)
              return result;
          }
        }
        if(entry_extracted) {
          /* If the path name does not look like an absolute path (i.e.: it
             does not start with a '/'), we probably need some server-dependent
             adjustments. For example, this is the case when connecting to
             an OS400 FTP server: this server supports two name syntaxes,
             the default one being incompatible with standard paths. In
             addition, this server switches automatically to the regular path
             syntax when one is encountered in a command: this results in
             having an entrypath in the wrong syntax when later used in CWD.
               The method used here is to check the server OS: we do it only
             if the path name looks strange to minimize overhead on other
             systems. */
          char *dir = Curl_dyn_ptr(&out);

          if(!ftpc->server_os && dir[0] != '/') {
            result = Curl_pp_sendf(data, &ftpc->pp, "%s", "SYST");
            if(result) {
              free(dir);
              return result;
            }
            Curl_safefree(ftpc->entrypath);
            ftpc->entrypath = dir; /* remember this */
            infof(data, "Entry path is '%s'", ftpc->entrypath);
            /* also save it where getinfo can access it: */
            data->state.most_recent_ftp_entrypath = ftpc->entrypath;
            ftp_state(data, FTP_SYST);
            break;
          }

          Curl_safefree(ftpc->entrypath);
          ftpc->entrypath = dir; /* remember this */
          infof(data, "Entry path is '%s'", ftpc->entrypath);
          /* also save it where getinfo can access it: */
          data->state.most_recent_ftp_entrypath = ftpc->entrypath;
        }
        else {
          /* could not get the path */
          Curl_dyn_free(&out);
          infof(data, "Failed to figure out path");
        }
      }
      ftp_state(data, FTP_STOP); /* we are done with the CONNECT phase! */
      CURL_TRC_FTP(data, "[%s] protocol connect phase DONE", FTP_DSTATE(data));
      break;

    case FTP_SYST:
      if(ftpcode == 215) {
        char *ptr = Curl_dyn_ptr(&pp->recvbuf) + 4; /* start on the first
                                                       letter */
        char *os;
        char *start;

        /* Reply format is like
           215<space><OS-name><space><commentary>
        */
        while(*ptr == ' ')
          ptr++;
        for(start = ptr; *ptr && *ptr != ' '; ptr++)
          ;
        os = Curl_memdup0(start, ptr - start);
        if(!os)
          return CURLE_OUT_OF_MEMORY;

        /* Check for special servers here. */
        if(strcasecompare(os, "OS/400")) {
          /* Force OS400 name format 1. */
          result = Curl_pp_sendf(data, &ftpc->pp, "%s", "SITE NAMEFMT 1");
          if(result) {
            free(os);
            return result;
          }
          /* remember target server OS */
          Curl_safefree(ftpc->server_os);
          ftpc->server_os = os;
          ftp_state(data, FTP_NAMEFMT);
          break;
        }
        /* Nothing special for the target server. */
        /* remember target server OS */
        Curl_safefree(ftpc->server_os);
        ftpc->server_os = os;
      }
      else {
        /* Cannot identify server OS. Continue anyway and cross fingers. */
      }

      ftp_state(data, FTP_STOP); /* we are done with the CONNECT phase! */
      CURL_TRC_FTP(data, "[%s] protocol connect phase DONE", FTP_DSTATE(data));
      break;

    case FTP_NAMEFMT:
      if(ftpcode == 250) {
        /* Name format change successful: reload initial path. */
        ftp_state_pwd(data, conn);
        break;
      }

      ftp_state(data, FTP_STOP); /* we are done with the CONNECT phase! */
      CURL_TRC_FTP(data, "[%s] protocol connect phase DONE", FTP_DSTATE(data));
      break;

    case FTP_QUOTE:
    case FTP_POSTQUOTE:
    case FTP_RETR_PREQUOTE:
    case FTP_STOR_PREQUOTE:
      if((ftpcode >= 400) && !ftpc->count2) {
        /* failure response code, and not allowed to fail */
        failf(data, "QUOT command failed with %03d", ftpcode);
        result = CURLE_QUOTE_ERROR;
      }
      else
        result = ftp_state_quote(data, FALSE, ftpc->state);
      break;

    case FTP_CWD:
      if(ftpcode/100 != 2) {
        /* failure to CWD there */
        if(data->set.ftp_create_missing_dirs &&
           ftpc->cwdcount && !ftpc->count2) {
          /* try making it */
          ftpc->count2++; /* counter to prevent CWD-MKD loops */

          /* count3 is set to allow MKD to fail once per dir. In the case when
          CWD fails and then MKD fails (due to another session raced it to
          create the dir) this then allows for a second try to CWD to it. */
          ftpc->count3 = (data->set.ftp_create_missing_dirs == 2) ? 1 : 0;

          result = Curl_pp_sendf(data, &ftpc->pp, "MKD %s",
                                 ftpc->dirs[ftpc->cwdcount - 1]);
          if(!result)
            ftp_state(data, FTP_MKD);
        }
        else {
          /* return failure */
          failf(data, "Server denied you to change to the given directory");
          ftpc->cwdfail = TRUE; /* do not remember this path as we failed
                                   to enter it */
          result = CURLE_REMOTE_ACCESS_DENIED;
        }
      }
      else {
        /* success */
        ftpc->count2 = 0;
        if(++ftpc->cwdcount <= ftpc->dirdepth)
          /* send next CWD */
          result = Curl_pp_sendf(data, &ftpc->pp, "CWD %s",
                                 ftpc->dirs[ftpc->cwdcount - 1]);
        else
          result = ftp_state_mdtm(data);
      }
      break;

    case FTP_MKD:
      if((ftpcode/100 != 2) && !ftpc->count3--) {
        /* failure to MKD the dir */
        failf(data, "Failed to MKD dir: %03d", ftpcode);
        result = CURLE_REMOTE_ACCESS_DENIED;
      }
      else {
        ftp_state(data, FTP_CWD);
        /* send CWD */
        result = Curl_pp_sendf(data, &ftpc->pp, "CWD %s",
                               ftpc->dirs[ftpc->cwdcount - 1]);
      }
      break;

    case FTP_MDTM:
      result = ftp_state_mdtm_resp(data, ftpcode);
      break;

    case FTP_TYPE:
    case FTP_LIST_TYPE:
    case FTP_RETR_TYPE:
    case FTP_STOR_TYPE:
      result = ftp_state_type_resp(data, ftpcode, ftpc->state);
      break;

    case FTP_SIZE:
    case FTP_RETR_SIZE:
    case FTP_STOR_SIZE:
      result = ftp_state_size_resp(data, ftpcode, ftpc->state);
      break;

    case FTP_REST:
    case FTP_RETR_REST:
      result = ftp_state_rest_resp(data, conn, ftpcode, ftpc->state);
      break;

    case FTP_PRET:
      if(ftpcode != 200) {
        /* there only is this one standard OK return code. */
        failf(data, "PRET command not accepted: %03d", ftpcode);
        return CURLE_FTP_PRET_FAILED;
      }
      result = ftp_state_use_pasv(data, conn);
      break;

    case FTP_PASV:
      result = ftp_state_pasv_resp(data, ftpcode);
      break;

    case FTP_PORT:
      result = ftp_state_port_resp(data, ftpcode);
      break;

    case FTP_LIST:
    case FTP_RETR:
      result = ftp_state_get_resp(data, ftpcode, ftpc->state);
      break;

    case FTP_STOR:
      result = ftp_state_stor_resp(data, ftpcode, ftpc->state);
      break;

    case FTP_QUIT:
    default:
      /* internal error */
      ftp_state(data, FTP_STOP);
      break;
    }
  } /* if(ftpcode) */

  return result;
}


/* called repeatedly until done from multi.c */
static CURLcode ftp_multi_statemach(struct Curl_easy *data,
                                    bool *done)
{
  struct connectdata *conn = data->conn;
  struct ftp_conn *ftpc = &conn->proto.ftpc;
  CURLcode result = Curl_pp_statemach(data, &ftpc->pp, FALSE, FALSE);

  /* Check for the state outside of the Curl_socket_check() return code checks
     since at times we are in fact already in this state when this function
     gets called. */
  *done = (ftpc->state == FTP_STOP);

  return result;
}

static CURLcode ftp_block_statemach(struct Curl_easy *data,
                                    struct connectdata *conn)
{
  struct ftp_conn *ftpc = &conn->proto.ftpc;
  struct pingpong *pp = &ftpc->pp;
  CURLcode result = CURLE_OK;

  while(ftpc->state != FTP_STOP) {
    result = Curl_pp_statemach(data, pp, TRUE, TRUE /* disconnecting */);
    if(result)
      break;
  }

  return result;
}

/*
 * ftp_connect() should do everything that is to be considered a part of
 * the connection phase.
 *
 * The variable 'done' points to will be TRUE if the protocol-layer connect
 * phase is done when this function returns, or FALSE if not.
 *
 */
static CURLcode ftp_connect(struct Curl_easy *data,
                            bool *done) /* see description above */
{
  CURLcode result;
  struct connectdata *conn = data->conn;
  struct ftp_conn *ftpc = &conn->proto.ftpc;
  struct pingpong *pp = &ftpc->pp;

  *done = FALSE; /* default to not done yet */

  /* We always support persistent connections on ftp */
  connkeep(conn, "FTP default");

  PINGPONG_SETUP(pp, ftp_statemachine, ftp_endofresp);

  if(Curl_conn_is_ssl(conn, FIRSTSOCKET)) {
    /* BLOCKING */
    result = Curl_conn_connect(data, FIRSTSOCKET, TRUE, done);
    if(result)
      return result;
    conn->bits.ftp_use_control_ssl = TRUE;
  }

  Curl_pp_init(pp); /* once per transfer */

  /* When we connect, we start in the state where we await the 220
     response */
  ftp_state(data, FTP_WAIT220);

  result = ftp_multi_statemach(data, done);

  return result;
}

/***********************************************************************
 *
 * ftp_done()
 *
 * The DONE function. This does what needs to be done after a single DO has
 * performed.
 *
 * Input argument is already checked for validity.
 */
static CURLcode ftp_done(struct Curl_easy *data, CURLcode status,
                         bool premature)
{
  struct connectdata *conn = data->conn;
  struct FTP *ftp = data->req.p.ftp;
  struct ftp_conn *ftpc = &conn->proto.ftpc;
  struct pingpong *pp = &ftpc->pp;
  ssize_t nread;
  int ftpcode;
  CURLcode result = CURLE_OK;
  char *rawPath = NULL;
  size_t pathLen = 0;

  if(!ftp)
    return CURLE_OK;

  switch(status) {
  case CURLE_BAD_DOWNLOAD_RESUME:
  case CURLE_FTP_WEIRD_PASV_REPLY:
  case CURLE_FTP_PORT_FAILED:
  case CURLE_FTP_ACCEPT_FAILED:
  case CURLE_FTP_ACCEPT_TIMEOUT:
  case CURLE_FTP_COULDNT_SET_TYPE:
  case CURLE_FTP_COULDNT_RETR_FILE:
  case CURLE_PARTIAL_FILE:
  case CURLE_UPLOAD_FAILED:
  case CURLE_REMOTE_ACCESS_DENIED:
  case CURLE_FILESIZE_EXCEEDED:
  case CURLE_REMOTE_FILE_NOT_FOUND:
  case CURLE_WRITE_ERROR:
    /* the connection stays alive fine even though this happened */
  case CURLE_OK: /* does not affect the control connection's status */
    if(!premature)
      break;

    /* until we cope better with prematurely ended requests, let them
     * fallback as if in complete failure */
    FALLTHROUGH();
  default:       /* by default, an error means the control connection is
                    wedged and should not be used anymore */
    ftpc->ctl_valid = FALSE;
    ftpc->cwdfail = TRUE; /* set this TRUE to prevent us to remember the
                             current path, as this connection is going */
    connclose(conn, "FTP ended with bad error code");
    result = status;      /* use the already set error code */
    break;
  }

  if(data->state.wildcardmatch) {
    if(data->set.chunk_end && ftpc->file) {
      Curl_set_in_callback(data, TRUE);
      data->set.chunk_end(data->set.wildcardptr);
      Curl_set_in_callback(data, FALSE);
    }
    ftpc->known_filesize = -1;
  }

  if(!result)
    /* get the url-decoded "raw" path */
    result = Curl_urldecode(ftp->path, 0, &rawPath, &pathLen,
                            REJECT_CTRL);
  if(result) {
    /* We can limp along anyway (and should try to since we may already be in
     * the error path) */
    ftpc->ctl_valid = FALSE; /* mark control connection as bad */
    connclose(conn, "FTP: out of memory!"); /* mark for connection closure */
    free(ftpc->prevpath);
    ftpc->prevpath = NULL; /* no path remembering */
  }
  else { /* remember working directory for connection reuse */
    if((data->set.ftp_filemethod == FTPFILE_NOCWD) && (rawPath[0] == '/'))
      free(rawPath); /* full path => no CWDs happened => keep ftpc->prevpath */
    else {
      free(ftpc->prevpath);

      if(!ftpc->cwdfail) {
        if(data->set.ftp_filemethod == FTPFILE_NOCWD)
          pathLen = 0; /* relative path => working directory is FTP home */
        else
          /* file is url-decoded */
          pathLen -= ftpc->file ? strlen(ftpc->file) : 0;

        rawPath[pathLen] = '\0';
        ftpc->prevpath = rawPath;
      }
      else {
        free(rawPath);
        ftpc->prevpath = NULL; /* no path */
      }
    }

    if(ftpc->prevpath)
      infof(data, "Remembering we are in dir \"%s\"", ftpc->prevpath);
  }

  /* free the dir tree and file parts */
  freedirs(ftpc);

  /* shut down the socket to inform the server we are done */

#ifdef UNDER_CE
  shutdown(conn->sock[SECONDARYSOCKET], 2);  /* SD_BOTH */
#endif

  if(conn->sock[SECONDARYSOCKET] != CURL_SOCKET_BAD) {
    if(!result && ftpc->dont_check && data->req.maxdownload > 0) {
      /* partial download completed */
      result = Curl_pp_sendf(data, pp, "%s", "ABOR");
      if(result) {
        failf(data, "Failure sending ABOR command: %s",
              curl_easy_strerror(result));
        ftpc->ctl_valid = FALSE; /* mark control connection as bad */
        connclose(conn, "ABOR command failed"); /* connection closure */
      }
    }

    close_secondarysocket(data);
  }

  if(!result && (ftp->transfer == PPTRANSFER_BODY) && ftpc->ctl_valid &&
     pp->pending_resp && !premature) {
    /*
     * Let's see what the server says about the transfer we just performed,
     * but lower the timeout as sometimes this connection has died while the
     * data has been transferred. This happens when doing through NATs etc that
     * abandon old silent connections.
     */
    timediff_t old_time = pp->response_time;

    pp->response_time = 60*1000; /* give it only a minute for now */
    pp->response = Curl_now(); /* timeout relative now */

    result = Curl_GetFTPResponse(data, &nread, &ftpcode);

    pp->response_time = old_time; /* set this back to previous value */

    if(!nread && (CURLE_OPERATION_TIMEDOUT == result)) {
      failf(data, "control connection looks dead");
      ftpc->ctl_valid = FALSE; /* mark control connection as bad */
      connclose(conn, "Timeout or similar in FTP DONE operation"); /* close */
    }

    if(result) {
      Curl_safefree(ftp->pathalloc);
      return result;
    }

    if(ftpc->dont_check && data->req.maxdownload > 0) {
      /* we have just sent ABOR and there is no reliable way to check if it was
       * successful or not; we have to close the connection now */
      infof(data, "partial download completed, closing connection");
      connclose(conn, "Partial download with no ability to check");
      return result;
    }

    if(!ftpc->dont_check) {
      /* 226 Transfer complete, 250 Requested file action okay, completed. */
      switch(ftpcode) {
      case 226:
      case 250:
        break;
      case 552:
        failf(data, "Exceeded storage allocation");
        result = CURLE_REMOTE_DISK_FULL;
        break;
      default:
        failf(data, "server did not report OK, got %d", ftpcode);
        result = CURLE_PARTIAL_FILE;
        break;
      }
    }
  }

  if(result || premature)
    /* the response code from the transfer showed an error already so no
       use checking further */
    ;
  else if(data->state.upload) {
    if((-1 != data->state.infilesize) &&
       (data->state.infilesize != data->req.writebytecount) &&
       !data->set.crlf &&
       (ftp->transfer == PPTRANSFER_BODY)) {
      failf(data, "Uploaded unaligned file size (%" FMT_OFF_T
            " out of %" FMT_OFF_T " bytes)",
            data->req.writebytecount, data->state.infilesize);
      result = CURLE_PARTIAL_FILE;
    }
  }
  else {
    if((-1 != data->req.size) &&
       (data->req.size != data->req.bytecount) &&
       (data->req.maxdownload != data->req.bytecount)) {
      failf(data, "Received only partial file: %" FMT_OFF_T " bytes",
            data->req.bytecount);
      result = CURLE_PARTIAL_FILE;
    }
    else if(!ftpc->dont_check &&
            !data->req.bytecount &&
            (data->req.size > 0)) {
      failf(data, "No data was received");
      result = CURLE_FTP_COULDNT_RETR_FILE;
    }
  }

  /* clear these for next connection */
  ftp->transfer = PPTRANSFER_BODY;
  ftpc->dont_check = FALSE;

  /* Send any post-transfer QUOTE strings? */
  if(!status && !result && !premature && data->set.postquote)
    result = ftp_sendquote(data, conn, data->set.postquote);
  CURL_TRC_FTP(data, "[%s] done, result=%d", FTP_DSTATE(data), result);
  Curl_safefree(ftp->pathalloc);
  return result;
}

/***********************************************************************
 *
 * ftp_sendquote()
 *
 * Where a 'quote' means a list of custom commands to send to the server.
 * The quote list is passed as an argument.
 *
 * BLOCKING
 */

static
CURLcode ftp_sendquote(struct Curl_easy *data,
                       struct connectdata *conn, struct curl_slist *quote)
{
  struct curl_slist *item;
  struct ftp_conn *ftpc = &conn->proto.ftpc;
  struct pingpong *pp = &ftpc->pp;

  item = quote;
  while(item) {
    if(item->data) {
      ssize_t nread;
      char *cmd = item->data;
      bool acceptfail = FALSE;
      CURLcode result;
      int ftpcode = 0;

      /* if a command starts with an asterisk, which a legal FTP command never
         can, the command will be allowed to fail without it causing any
         aborts or cancels etc. It will cause libcurl to act as if the command
         is successful, whatever the server responds. */

      if(cmd[0] == '*') {
        cmd++;
        acceptfail = TRUE;
      }

      result = Curl_pp_sendf(data, &ftpc->pp, "%s", cmd);
      if(!result) {
        pp->response = Curl_now(); /* timeout relative now */
        result = Curl_GetFTPResponse(data, &nread, &ftpcode);
      }
      if(result)
        return result;

      if(!acceptfail && (ftpcode >= 400)) {
        failf(data, "QUOT string not accepted: %s", cmd);
        return CURLE_QUOTE_ERROR;
      }
    }

    item = item->next;
  }

  return CURLE_OK;
}

/***********************************************************************
 *
 * ftp_need_type()
 *
 * Returns TRUE if we in the current situation should send TYPE
 */
static int ftp_need_type(struct connectdata *conn,
                         bool ascii_wanted)
{
  return conn->proto.ftpc.transfertype != (ascii_wanted ? 'A' : 'I');
}

/***********************************************************************
 *
 * ftp_nb_type()
 *
 * Set TYPE. We only deal with ASCII or BINARY so this function
 * sets one of them.
 * If the transfer type is not sent, simulate on OK response in newstate
 */
static CURLcode ftp_nb_type(struct Curl_easy *data,
                            struct connectdata *conn,
                            bool ascii, ftpstate newstate)
{
  struct ftp_conn *ftpc = &conn->proto.ftpc;
  CURLcode result;
  char want = (char)(ascii ? 'A' : 'I');

  if(ftpc->transfertype == want) {
    ftp_state(data, newstate);
    return ftp_state_type_resp(data, 200, newstate);
  }

  result = Curl_pp_sendf(data, &ftpc->pp, "TYPE %c", want);
  if(!result) {
    ftp_state(data, newstate);

    /* keep track of our current transfer type */
    ftpc->transfertype = want;
  }
  return result;
}

/***************************************************************************
 *
 * ftp_pasv_verbose()
 *
 * This function only outputs some informationals about this second connection
 * when we have issued a PASV command before and thus we have connected to a
 * possibly new IP address.
 *
 */
#ifndef CURL_DISABLE_VERBOSE_STRINGS
static void
ftp_pasv_verbose(struct Curl_easy *data,
                 struct Curl_addrinfo *ai,
                 char *newhost, /* ASCII version */
                 int port)
{
  char buf[256];
  Curl_printable_address(ai, buf, sizeof(buf));
  infof(data, "Connecting to %s (%s) port %d", newhost, buf, port);
}
#endif

/*
 * ftp_do_more()
 *
 * This function shall be called when the second FTP (data) connection is
 * connected.
 *
 * 'complete' can return 0 for incomplete, 1 for done and -1 for go back
 * (which basically is only for when PASV is being sent to retry a failed
 * EPSV).
 */

static CURLcode ftp_do_more(struct Curl_easy *data, int *completep)
{
  struct connectdata *conn = data->conn;
  struct ftp_conn *ftpc = &conn->proto.ftpc;
  CURLcode result = CURLE_OK;
  bool connected = FALSE;
  bool complete = FALSE;

  /* the ftp struct is inited in ftp_connect(). If we are connecting to an HTTP
   * proxy then the state will not be valid until after that connection is
   * complete */
  struct FTP *ftp = NULL;

  /* if the second connection has been set up, try to connect it fully
   * to the remote host. This may not complete at this time, for several
   * reasons:
   * - we do EPTR and the server will not connect to our listen socket
   *   until we send more FTP commands
   * - an SSL filter is in place and the server will not start the TLS
   *   handshake until we send more FTP commands
   */
  if(conn->cfilter[SECONDARYSOCKET]) {
    bool is_eptr = Curl_conn_is_tcp_listen(data, SECONDARYSOCKET);
    result = Curl_conn_connect(data, SECONDARYSOCKET, FALSE, &connected);
    if(result || (!connected && !is_eptr &&
                  !Curl_conn_is_ip_connected(data, SECONDARYSOCKET))) {
      if(result && !is_eptr && (ftpc->count1 == 0)) {
        *completep = -1; /* go back to DOING please */
        /* this is a EPSV connect failing, try PASV instead */
        return ftp_epsv_disable(data, conn);
      }
      *completep = (int)complete;
      return result;
    }
  }

  /* Curl_proxy_connect might have moved the protocol state */
  ftp = data->req.p.ftp;

  if(ftpc->state) {
    /* already in a state so skip the initial commands.
       They are only done to kickstart the do_more state */
    result = ftp_multi_statemach(data, &complete);

    *completep = (int)complete;

    /* if we got an error or if we do not wait for a data connection return
       immediately */
    if(result || !ftpc->wait_data_conn)
      return result;

    /* if we reach the end of the FTP state machine here, *complete will be
       TRUE but so is ftpc->wait_data_conn, which says we need to wait for the
       data connection and therefore we are not actually complete */
    *completep = 0;
  }

  if(ftp->transfer <= PPTRANSFER_INFO) {
    /* a transfer is about to take place, or if not a filename was given so we
       will do a SIZE on it later and then we need the right TYPE first */

    if(ftpc->wait_data_conn) {
      bool serv_conned;

      result = Curl_conn_connect(data, SECONDARYSOCKET, FALSE, &serv_conned);
      if(result)
        return result; /* Failed to accept data connection */

      if(serv_conned) {
        /* It looks data connection is established */
        ftpc->wait_data_conn = FALSE;
        result = InitiateTransfer(data);

        if(result)
          return result;

        *completep = 1; /* this state is now complete when the server has
                           connected back to us */
      }
      else {
        result = ftp_check_ctrl_on_data_wait(data);
        if(result)
          return result;
      }
    }
    else if(data->state.upload) {
      result = ftp_nb_type(data, conn, data->state.prefer_ascii,
                           FTP_STOR_TYPE);
      if(result)
        return result;

      result = ftp_multi_statemach(data, &complete);
      *completep = (int)complete;
    }
    else {
      /* download */
      ftp->downloadsize = -1; /* unknown as of yet */

      result = Curl_range(data);

      if(result == CURLE_OK && data->req.maxdownload >= 0) {
        /* Do not check for successful transfer */
        ftpc->dont_check = TRUE;
      }

      if(result)
        ;
      else if(data->state.list_only || !ftpc->file) {
        /* The specified path ends with a slash, and therefore we think this
           is a directory that is requested, use LIST. But before that we
           need to set ASCII transfer mode. */

        /* But only if a body transfer was requested. */
        if(ftp->transfer == PPTRANSFER_BODY) {
          result = ftp_nb_type(data, conn, TRUE, FTP_LIST_TYPE);
          if(result)
            return result;
        }
        /* otherwise just fall through */
      }
      else {
        result = ftp_nb_type(data, conn, data->state.prefer_ascii,
                             FTP_RETR_TYPE);
        if(result)
          return result;
      }

      result = ftp_multi_statemach(data, &complete);
      *completep = (int)complete;
    }
    return result;
  }

  /* no data to transfer */
  Curl_xfer_setup_nop(data);

  if(!ftpc->wait_data_conn) {
    /* no waiting for the data connection so this is now complete */
    *completep = 1;
    CURL_TRC_FTP(data, "[%s] DO-MORE phase ends with %d", FTP_DSTATE(data),
                 (int)result);
  }

  return result;
}



/***********************************************************************
 *
 * ftp_perform()
 *
 * This is the actual DO function for FTP. Get a file/directory according to
 * the options previously setup.
 */

static
CURLcode ftp_perform(struct Curl_easy *data,
                     bool *connected,  /* connect status after PASV / PORT */
                     bool *dophase_done)
{
  /* this is FTP and no proxy */
  CURLcode result = CURLE_OK;

  CURL_TRC_FTP(data, "[%s] DO phase starts", FTP_DSTATE(data));

  if(data->req.no_body) {
    /* requested no body means no transfer... */
    struct FTP *ftp = data->req.p.ftp;
    ftp->transfer = PPTRANSFER_INFO;
  }

  *dophase_done = FALSE; /* not done yet */

  /* start the first command in the DO phase */
  result = ftp_state_quote(data, TRUE, FTP_QUOTE);
  if(result)
    return result;

  /* run the state-machine */
  result = ftp_multi_statemach(data, dophase_done);

  *connected = Curl_conn_is_connected(data->conn, SECONDARYSOCKET);

  if(*connected)
    infof(data, "[FTP] [%s] perform, DATA connection established",
          FTP_DSTATE(data));
  else
    CURL_TRC_FTP(data, "[%s] perform, awaiting DATA connect",
                 FTP_DSTATE(data));

  if(*dophase_done)
    CURL_TRC_FTP(data, "[%s] DO phase is complete1", FTP_DSTATE(data));

  return result;
}

static void wc_data_dtor(void *ptr)
{
  struct ftp_wc *ftpwc = ptr;
  if(ftpwc && ftpwc->parser)
    Curl_ftp_parselist_data_free(&ftpwc->parser);
  free(ftpwc);
}

static CURLcode init_wc_data(struct Curl_easy *data)
{
  char *last_slash;
  struct FTP *ftp = data->req.p.ftp;
  char *path = ftp->path;
  struct WildcardData *wildcard = data->wildcard;
  CURLcode result = CURLE_OK;
  struct ftp_wc *ftpwc = NULL;

  last_slash = strrchr(ftp->path, '/');
  if(last_slash) {
    last_slash++;
    if(last_slash[0] == '\0') {
      wildcard->state = CURLWC_CLEAN;
      return ftp_parse_url_path(data);
    }
    wildcard->pattern = strdup(last_slash);
    if(!wildcard->pattern)
      return CURLE_OUT_OF_MEMORY;
    last_slash[0] = '\0'; /* cut file from path */
  }
  else { /* there is only 'wildcard pattern' or nothing */
    if(path[0]) {
      wildcard->pattern = strdup(path);
      if(!wildcard->pattern)
        return CURLE_OUT_OF_MEMORY;
      path[0] = '\0';
    }
    else { /* only list */
      wildcard->state = CURLWC_CLEAN;
      return ftp_parse_url_path(data);
    }
  }

  /* program continues only if URL is not ending with slash, allocate needed
     resources for wildcard transfer */

  /* allocate ftp protocol specific wildcard data */
  ftpwc = calloc(1, sizeof(struct ftp_wc));
  if(!ftpwc) {
    result = CURLE_OUT_OF_MEMORY;
    goto fail;
  }

  /* INITIALIZE parselist structure */
  ftpwc->parser = Curl_ftp_parselist_data_alloc();
  if(!ftpwc->parser) {
    result = CURLE_OUT_OF_MEMORY;
    goto fail;
  }

  wildcard->ftpwc = ftpwc; /* put it to the WildcardData tmp pointer */
  wildcard->dtor = wc_data_dtor;

  /* wildcard does not support NOCWD option (assert it?) */
  if(data->set.ftp_filemethod == FTPFILE_NOCWD)
    data->set.ftp_filemethod = FTPFILE_MULTICWD;

  /* try to parse ftp URL */
  result = ftp_parse_url_path(data);
  if(result) {
    goto fail;
  }

  wildcard->path = strdup(ftp->path);
  if(!wildcard->path) {
    result = CURLE_OUT_OF_MEMORY;
    goto fail;
  }

  /* backup old write_function */
  ftpwc->backup.write_function = data->set.fwrite_func;
  /* parsing write function */
  data->set.fwrite_func = Curl_ftp_parselist;
  /* backup old file descriptor */
  ftpwc->backup.file_descriptor = data->set.out;
  /* let the writefunc callback know the transfer */
  data->set.out = data;

  infof(data, "Wildcard - Parsing started");
  return CURLE_OK;

fail:
  if(ftpwc) {
    Curl_ftp_parselist_data_free(&ftpwc->parser);
    free(ftpwc);
  }
  Curl_safefree(wildcard->pattern);
  wildcard->dtor = ZERO_NULL;
  wildcard->ftpwc = NULL;
  return result;
}

static CURLcode wc_statemach(struct Curl_easy *data)
{
  struct WildcardData * const wildcard = data->wildcard;
  struct connectdata *conn = data->conn;
  CURLcode result = CURLE_OK;

  for(;;) {
    switch(wildcard->state) {
    case CURLWC_INIT:
      result = init_wc_data(data);
      if(wildcard->state == CURLWC_CLEAN)
        /* only listing! */
        return result;
      wildcard->state = result ? CURLWC_ERROR : CURLWC_MATCHING;
      return result;

    case CURLWC_MATCHING: {
      /* In this state is LIST response successfully parsed, so lets restore
         previous WRITEFUNCTION callback and WRITEDATA pointer */
      struct ftp_wc *ftpwc = wildcard->ftpwc;
      data->set.fwrite_func = ftpwc->backup.write_function;
      data->set.out = ftpwc->backup.file_descriptor;
      ftpwc->backup.write_function = ZERO_NULL;
      ftpwc->backup.file_descriptor = NULL;
      wildcard->state = CURLWC_DOWNLOADING;

      if(Curl_ftp_parselist_geterror(ftpwc->parser)) {
        /* error found in LIST parsing */
        wildcard->state = CURLWC_CLEAN;
        continue;
      }
      if(Curl_llist_count(&wildcard->filelist) == 0) {
        /* no corresponding file */
        wildcard->state = CURLWC_CLEAN;
        return CURLE_REMOTE_FILE_NOT_FOUND;
      }
      continue;
    }

    case CURLWC_DOWNLOADING: {
      /* filelist has at least one file, lets get first one */
      struct ftp_conn *ftpc = &conn->proto.ftpc;
      struct Curl_llist_node *head = Curl_llist_head(&wildcard->filelist);
      struct curl_fileinfo *finfo = Curl_node_elem(head);
      struct FTP *ftp = data->req.p.ftp;

      char *tmp_path = aprintf("%s%s", wildcard->path, finfo->filename);
      if(!tmp_path)
        return CURLE_OUT_OF_MEMORY;

      /* switch default ftp->path and tmp_path */
      free(ftp->pathalloc);
      ftp->pathalloc = ftp->path = tmp_path;

      infof(data, "Wildcard - START of \"%s\"", finfo->filename);
      if(data->set.chunk_bgn) {
        long userresponse;
        Curl_set_in_callback(data, TRUE);
        userresponse = data->set.chunk_bgn(
          finfo, data->set.wildcardptr,
          (int)Curl_llist_count(&wildcard->filelist));
        Curl_set_in_callback(data, FALSE);
        switch(userresponse) {
        case CURL_CHUNK_BGN_FUNC_SKIP:
          infof(data, "Wildcard - \"%s\" skipped by user",
                finfo->filename);
          wildcard->state = CURLWC_SKIP;
          continue;
        case CURL_CHUNK_BGN_FUNC_FAIL:
          return CURLE_CHUNK_FAILED;
        }
      }

      if(finfo->filetype != CURLFILETYPE_FILE) {
        wildcard->state = CURLWC_SKIP;
        continue;
      }

      if(finfo->flags & CURLFINFOFLAG_KNOWN_SIZE)
        ftpc->known_filesize = finfo->size;

      result = ftp_parse_url_path(data);
      if(result)
        return result;

      /* we do not need the Curl_fileinfo of first file anymore */
      Curl_node_remove(Curl_llist_head(&wildcard->filelist));

      if(Curl_llist_count(&wildcard->filelist) == 0) {
        /* remains only one file to down. */
        wildcard->state = CURLWC_CLEAN;
        /* after that will be ftp_do called once again and no transfer
           will be done because of CURLWC_CLEAN state */
        return CURLE_OK;
      }
      return result;
    }

    case CURLWC_SKIP: {
      if(data->set.chunk_end) {
        Curl_set_in_callback(data, TRUE);
        data->set.chunk_end(data->set.wildcardptr);
        Curl_set_in_callback(data, FALSE);
      }
      Curl_node_remove(Curl_llist_head(&wildcard->filelist));
      wildcard->state = (Curl_llist_count(&wildcard->filelist) == 0) ?
        CURLWC_CLEAN : CURLWC_DOWNLOADING;
      continue;
    }

    case CURLWC_CLEAN: {
      struct ftp_wc *ftpwc = wildcard->ftpwc;
      result = CURLE_OK;
      if(ftpwc)
        result = Curl_ftp_parselist_geterror(ftpwc->parser);

      wildcard->state = result ? CURLWC_ERROR : CURLWC_DONE;
      return result;
    }

    case CURLWC_DONE:
    case CURLWC_ERROR:
    case CURLWC_CLEAR:
      if(wildcard->dtor) {
        wildcard->dtor(wildcard->ftpwc);
        wildcard->ftpwc = NULL;
      }
      return result;
    }
  }
  /* UNREACHABLE */
}

/***********************************************************************
 *
 * ftp_do()
 *
 * This function is registered as 'curl_do' function. It decodes the path
 * parts etc as a wrapper to the actual DO function (ftp_perform).
 *
 * The input argument is already checked for validity.
 */
static CURLcode ftp_do(struct Curl_easy *data, bool *done)
{
  CURLcode result = CURLE_OK;
  struct connectdata *conn = data->conn;
  struct ftp_conn *ftpc = &conn->proto.ftpc;

  *done = FALSE; /* default to false */
  ftpc->wait_data_conn = FALSE; /* default to no such wait */

#ifdef CURL_PREFER_LF_LINEENDS
  {
    /* FTP data may need conversion. */
    struct Curl_cwriter *ftp_lc_writer;

    result = Curl_cwriter_create(&ftp_lc_writer, data, &ftp_cw_lc,
                                 CURL_CW_CONTENT_DECODE);
    if(result)
      return result;

    result = Curl_cwriter_add(data, ftp_lc_writer);
    if(result) {
      Curl_cwriter_free(data, ftp_lc_writer);
      return result;
    }
  }
#endif /* CURL_PREFER_LF_LINEENDS */

  if(data->state.wildcardmatch) {
    result = wc_statemach(data);
    if(data->wildcard->state == CURLWC_SKIP ||
       data->wildcard->state == CURLWC_DONE) {
      /* do not call ftp_regular_transfer */
      return CURLE_OK;
    }
    if(result) /* error, loop or skipping the file */
      return result;
  }
  else { /* no wildcard FSM needed */
    result = ftp_parse_url_path(data);
    if(result)
      return result;
  }

  result = ftp_regular_transfer(data, done);

  return result;
}

/***********************************************************************
 *
 * ftp_quit()
 *
 * This should be called before calling sclose() on an ftp control connection
 * (not data connections). We should then wait for the response from the
 * server before returning. The calling code should then try to close the
 * connection.
 *
 */
static CURLcode ftp_quit(struct Curl_easy *data, struct connectdata *conn)
{
  CURLcode result = CURLE_OK;

  if(conn->proto.ftpc.ctl_valid) {
    result = Curl_pp_sendf(data, &conn->proto.ftpc.pp, "%s", "QUIT");
    if(result) {
      failf(data, "Failure sending QUIT command: %s",
            curl_easy_strerror(result));
      conn->proto.ftpc.ctl_valid = FALSE; /* mark control connection as bad */
      connclose(conn, "QUIT command failed"); /* mark for connection closure */
      ftp_state(data, FTP_STOP);
      return result;
    }

    ftp_state(data, FTP_QUIT);

    result = ftp_block_statemach(data, conn);
  }

  return result;
}

/***********************************************************************
 *
 * ftp_disconnect()
 *
 * Disconnect from an FTP server. Cleanup protocol-specific per-connection
 * resources. BLOCKING.
 */
static CURLcode ftp_disconnect(struct Curl_easy *data,
                               struct connectdata *conn,
                               bool dead_connection)
{
  struct ftp_conn *ftpc = &conn->proto.ftpc;
  struct pingpong *pp = &ftpc->pp;

  /* We cannot send quit unconditionally. If this connection is stale or
     bad in any way, sending quit and waiting around here will make the
     disconnect wait in vain and cause more problems than we need to.

     ftp_quit() will check the state of ftp->ctl_valid. If it is ok it
     will try to send the QUIT command, otherwise it will just return.
  */
  if(dead_connection)
    ftpc->ctl_valid = FALSE;

  /* The FTP session may or may not have been allocated/setup at this point! */
  (void)ftp_quit(data, conn); /* ignore errors on the QUIT */

  if(ftpc->entrypath) {
    if(data->state.most_recent_ftp_entrypath == ftpc->entrypath) {
      data->state.most_recent_ftp_entrypath = NULL;
    }
    Curl_safefree(ftpc->entrypath);
  }

  freedirs(ftpc);
  Curl_safefree(ftpc->account);
  Curl_safefree(ftpc->alternative_to_user);
  Curl_safefree(ftpc->prevpath);
  Curl_safefree(ftpc->server_os);
  Curl_pp_disconnect(pp);
  Curl_sec_end(conn);
  return CURLE_OK;
}

/***********************************************************************
 *
 * ftp_parse_url_path()
 *
 * Parse the URL path into separate path components.
 *
 */
static
CURLcode ftp_parse_url_path(struct Curl_easy *data)
{
  /* the ftp struct is already inited in ftp_connect() */
  struct FTP *ftp = data->req.p.ftp;
  struct connectdata *conn = data->conn;
  struct ftp_conn *ftpc = &conn->proto.ftpc;
  const char *slashPos = NULL;
  const char *fileName = NULL;
  CURLcode result = CURLE_OK;
  char *rawPath = NULL; /* url-decoded "raw" path */
  size_t pathLen = 0;

  ftpc->ctl_valid = FALSE;
  ftpc->cwdfail = FALSE;

  /* url-decode ftp path before further evaluation */
  result = Curl_urldecode(ftp->path, 0, &rawPath, &pathLen, REJECT_CTRL);
  if(result) {
    failf(data, "path contains control characters");
    return result;
  }

  switch(data->set.ftp_filemethod) {
    case FTPFILE_NOCWD: /* fastest, but less standard-compliant */

      if((pathLen > 0) && (rawPath[pathLen - 1] != '/'))
        fileName = rawPath;  /* this is a full file path */
      /*
        else: ftpc->file is not used anywhere other than for operations on
              a file. In other words, never for directory operations.
              So we can safely leave filename as NULL here and use it as a
              argument in dir/file decisions.
      */
      break;

    case FTPFILE_SINGLECWD:
      slashPos = strrchr(rawPath, '/');
      if(slashPos) {
        /* get path before last slash, except for / */
        size_t dirlen = slashPos - rawPath;
        if(dirlen == 0)
          dirlen = 1;

        ftpc->dirs = calloc(1, sizeof(ftpc->dirs[0]));
        if(!ftpc->dirs) {
          free(rawPath);
          return CURLE_OUT_OF_MEMORY;
        }

        ftpc->dirs[0] = Curl_memdup0(rawPath, dirlen);
        if(!ftpc->dirs[0]) {
          free(rawPath);
          return CURLE_OUT_OF_MEMORY;
        }

        ftpc->dirdepth = 1; /* we consider it to be a single dir */
        fileName = slashPos + 1; /* rest is filename */
      }
      else
        fileName = rawPath; /* filename only (or empty) */
      break;

    default: /* allow pretty much anything */
    case FTPFILE_MULTICWD: {
      /* current position: begin of next path component */
      const char *curPos = rawPath;

      /* number of entries allocated for the 'dirs' array */
      size_t dirAlloc = 0;
      const char *str = rawPath;
      for(; *str != 0; ++str)
        if(*str == '/')
          ++dirAlloc;

      if(dirAlloc) {
        ftpc->dirs = calloc(dirAlloc, sizeof(ftpc->dirs[0]));
        if(!ftpc->dirs) {
          free(rawPath);
          return CURLE_OUT_OF_MEMORY;
        }

        /* parse the URL path into separate path components */
        /* !checksrc! disable EQUALSNULL 1 */
        while((slashPos = strchr(curPos, '/')) != NULL) {
          size_t compLen = slashPos - curPos;

          /* path starts with a slash: add that as a directory */
          if((compLen == 0) && (ftpc->dirdepth == 0))
            ++compLen;

          /* we skip empty path components, like "x//y" since the FTP command
             CWD requires a parameter and a non-existent parameter a) does not
             work on many servers and b) has no effect on the others. */
          if(compLen > 0) {
            char *comp = Curl_memdup0(curPos, compLen);
            if(!comp) {
              free(rawPath);
              return CURLE_OUT_OF_MEMORY;
            }
            ftpc->dirs[ftpc->dirdepth++] = comp;
          }
          curPos = slashPos + 1;
        }
      }
      DEBUGASSERT((size_t)ftpc->dirdepth <= dirAlloc);
      fileName = curPos; /* the rest is the filename (or empty) */
    }
    break;
  } /* switch */

  if(fileName && *fileName)
    ftpc->file = strdup(fileName);
  else
    ftpc->file = NULL; /* instead of point to a zero byte,
                            we make it a NULL pointer */

  if(data->state.upload && !ftpc->file && (ftp->transfer == PPTRANSFER_BODY)) {
    /* We need a filename when uploading. Return error! */
    failf(data, "Uploading to a URL without a filename");
    free(rawPath);
    return CURLE_URL_MALFORMAT;
  }

  ftpc->cwddone = FALSE; /* default to not done */

  if((data->set.ftp_filemethod == FTPFILE_NOCWD) && (rawPath[0] == '/'))
    ftpc->cwddone = TRUE; /* skip CWD for absolute paths */
  else { /* newly created FTP connections are already in entry path */
    const char *oldPath = conn->bits.reuse ? ftpc->prevpath : "";
    if(oldPath) {
      size_t n = pathLen;
      if(data->set.ftp_filemethod == FTPFILE_NOCWD)
        n = 0; /* CWD to entry for relative paths */
      else
        n -= ftpc->file ? strlen(ftpc->file) : 0;

      if((strlen(oldPath) == n) && rawPath && !strncmp(rawPath, oldPath, n)) {
        infof(data, "Request has same path as previous transfer");
        ftpc->cwddone = TRUE;
      }
    }
  }

  free(rawPath);
  return CURLE_OK;
}

/* call this when the DO phase has completed */
static CURLcode ftp_dophase_done(struct Curl_easy *data, bool connected)
{
  struct connectdata *conn = data->conn;
  struct FTP *ftp = data->req.p.ftp;
  struct ftp_conn *ftpc = &conn->proto.ftpc;

  if(connected) {
    int completed;
    CURLcode result = ftp_do_more(data, &completed);

    if(result) {
      close_secondarysocket(data);
      return result;
    }
  }

  if(ftp->transfer != PPTRANSFER_BODY)
    /* no data to transfer */
    Curl_xfer_setup_nop(data);
  else if(!connected)
    /* since we did not connect now, we want do_more to get called */
    conn->bits.do_more = TRUE;

  ftpc->ctl_valid = TRUE; /* seems good */

  return CURLE_OK;
}

/* called from multi.c while DOing */
static CURLcode ftp_doing(struct Curl_easy *data,
                          bool *dophase_done)
{
  CURLcode result = ftp_multi_statemach(data, dophase_done);

  if(result)
    CURL_TRC_FTP(data, "[%s] DO phase failed", FTP_DSTATE(data));
  else if(*dophase_done) {
    result = ftp_dophase_done(data, FALSE /* not connected */);

    CURL_TRC_FTP(data, "[%s] DO phase is complete2", FTP_DSTATE(data));
  }
  return result;
}

/***********************************************************************
 *
 * ftp_regular_transfer()
 *
 * The input argument is already checked for validity.
 *
 * Performs all commands done before a regular transfer between a local and a
 * remote host.
 *
 * ftp->ctl_valid starts out as FALSE, and gets set to TRUE if we reach the
 * ftp_done() function without finding any major problem.
 */
static
CURLcode ftp_regular_transfer(struct Curl_easy *data,
                              bool *dophase_done)
{
  CURLcode result = CURLE_OK;
  bool connected = FALSE;
  struct connectdata *conn = data->conn;
  struct ftp_conn *ftpc = &conn->proto.ftpc;
  data->req.size = -1; /* make sure this is unknown at this point */

  Curl_pgrsSetUploadCounter(data, 0);
  Curl_pgrsSetDownloadCounter(data, 0);
  Curl_pgrsSetUploadSize(data, -1);
  Curl_pgrsSetDownloadSize(data, -1);

  ftpc->ctl_valid = TRUE; /* starts good */

  result = ftp_perform(data,
                       &connected, /* have we connected after PASV/PORT */
                       dophase_done); /* all commands in the DO-phase done? */

  if(!result) {

    if(!*dophase_done)
      /* the DO phase has not completed yet */
      return CURLE_OK;

    result = ftp_dophase_done(data, connected);

    if(result)
      return result;
  }
  else
    freedirs(ftpc);

  return result;
}

static CURLcode ftp_setup_connection(struct Curl_easy *data,
                                     struct connectdata *conn)
{
  char *type;
  struct FTP *ftp;
  CURLcode result = CURLE_OK;
  struct ftp_conn *ftpc = &conn->proto.ftpc;

  ftp = calloc(1, sizeof(struct FTP));
  if(!ftp)
    return CURLE_OUT_OF_MEMORY;

  /* clone connection related data that is FTP specific */
  if(data->set.str[STRING_FTP_ACCOUNT]) {
    ftpc->account = strdup(data->set.str[STRING_FTP_ACCOUNT]);
    if(!ftpc->account) {
      free(ftp);
      return CURLE_OUT_OF_MEMORY;
    }
  }
  if(data->set.str[STRING_FTP_ALTERNATIVE_TO_USER]) {
    ftpc->alternative_to_user =
      strdup(data->set.str[STRING_FTP_ALTERNATIVE_TO_USER]);
    if(!ftpc->alternative_to_user) {
      Curl_safefree(ftpc->account);
      free(ftp);
      return CURLE_OUT_OF_MEMORY;
    }
  }
  data->req.p.ftp = ftp;

  ftp->path = &data->state.up.path[1]; /* do not include the initial slash */

  /* FTP URLs support an extension like ";type=<typecode>" that
   * we will try to get now! */
  type = strstr(ftp->path, ";type=");

  if(!type)
    type = strstr(conn->host.rawalloc, ";type=");

  if(type) {
    char command;
    *type = 0;                     /* it was in the middle of the hostname */
    command = Curl_raw_toupper(type[6]);

    switch(command) {
    case 'A': /* ASCII mode */
      data->state.prefer_ascii = TRUE;
      break;

    case 'D': /* directory mode */
      data->state.list_only = TRUE;
      break;

    case 'I': /* binary mode */
    default:
      /* switch off ASCII */
      data->state.prefer_ascii = FALSE;
      break;
    }
  }

  /* get some initial data into the ftp struct */
  ftp->transfer = PPTRANSFER_BODY;
  ftp->downloadsize = 0;
  ftpc->known_filesize = -1; /* unknown size for now */
  ftpc->use_ssl = data->set.use_ssl;
  ftpc->ccc = data->set.ftp_ccc;

  CURL_TRC_FTP(data, "[%s] setup connection -> %d", FTP_CSTATE(conn), result);
  return result;
}

#endif /* CURL_DISABLE_FTP */
