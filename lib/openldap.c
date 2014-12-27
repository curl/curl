/***************************************************************************
 *                      _   _ ____  _
 *  Project         ___| | | |  _ \| |
 *                 / __| | | | |_) | |
 *                | (__| |_| |  _ <| |___
 *                 \___|\___/|_| \_\_____|
 *
 * Copyright (C) 2010, 2013, Howard Chu, <hyc@openldap.org>
 * Copyright (C) 2011 - 2014, Daniel Stenberg, <daniel@haxx.se>, et al.
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

#include "curl_setup.h"

#if !defined(CURL_DISABLE_LDAP) && defined(USE_OPENLDAP)

/*
 * Notice that USE_OPENLDAP is only a source code selection switch. When
 * libcurl is built with USE_OPENLDAP defined the libcurl source code that
 * gets compiled is the code from openldap.c, otherwise the code that gets
 * compiled is the code from ldap.c.
 *
 * When USE_OPENLDAP is defined a recent version of the OpenLDAP library
 * might be required for compilation and runtime. In order to use ancient
 * OpenLDAP library versions, USE_OPENLDAP shall not be defined.
 */

#include <ldap.h>

#include "urldata.h"
#include <curl/curl.h>
#include "sendf.h"
#include "vtls/vtls.h"
#include "transfer.h"
#include "curl_ldap.h"
#include "curl_memory.h"
#include "curl_base64.h"
#include "connect.h"

#define _MPRINTF_REPLACE /* use our functions only */
#include <curl/mprintf.h>

#include "memdebug.h"

#ifndef _LDAP_PVT_H
extern int ldap_pvt_url_scheme2proto(const char *);
extern int ldap_init_fd(ber_socket_t fd, int proto, const char *url,
                        LDAP **ld);
#endif

static CURLcode ldap_setup_connection(struct connectdata *conn);
static CURLcode ldap_do(struct connectdata *conn, bool *done);
static CURLcode ldap_done(struct connectdata *conn, CURLcode, bool);
static CURLcode ldap_connect(struct connectdata *conn, bool *done);
static CURLcode ldap_connecting(struct connectdata *conn, bool *done);
static CURLcode ldap_disconnect(struct connectdata *conn, bool dead);

static Curl_recv ldap_recv;

/*
 * LDAP protocol handler.
 */

const struct Curl_handler Curl_handler_ldap = {
  "LDAP",                               /* scheme */
  ldap_setup_connection,                /* setup_connection */
  ldap_do,                              /* do_it */
  ldap_done,                            /* done */
  ZERO_NULL,                            /* do_more */
  ldap_connect,                         /* connect_it */
  ldap_connecting,                      /* connecting */
  ZERO_NULL,                            /* doing */
  ZERO_NULL,                            /* proto_getsock */
  ZERO_NULL,                            /* doing_getsock */
  ZERO_NULL,                            /* domore_getsock */
  ZERO_NULL,                            /* perform_getsock */
  ldap_disconnect,                      /* disconnect */
  ZERO_NULL,                            /* readwrite */
  PORT_LDAP,                            /* defport */
  CURLPROTO_LDAP,                       /* protocol */
  PROTOPT_NONE                          /* flags */
};

#ifdef USE_SSL
/*
 * LDAPS protocol handler.
 */

const struct Curl_handler Curl_handler_ldaps = {
  "LDAPS",                              /* scheme */
  ldap_setup_connection,                /* setup_connection */
  ldap_do,                              /* do_it */
  ldap_done,                            /* done */
  ZERO_NULL,                            /* do_more */
  ldap_connect,                         /* connect_it */
  ldap_connecting,                      /* connecting */
  ZERO_NULL,                            /* doing */
  ZERO_NULL,                            /* proto_getsock */
  ZERO_NULL,                            /* doing_getsock */
  ZERO_NULL,                            /* domore_getsock */
  ZERO_NULL,                            /* perform_getsock */
  ldap_disconnect,                      /* disconnect */
  ZERO_NULL,                            /* readwrite */
  PORT_LDAPS,                           /* defport */
  CURLPROTO_LDAP,                       /* protocol */
  PROTOPT_SSL                           /* flags */
};
#endif

static const char *url_errs[] = {
  "success",
  "out of memory",
  "bad parameter",
  "unrecognized scheme",
  "unbalanced delimiter",
  "bad URL",
  "bad host or port",
  "bad or missing attributes",
  "bad or missing scope",
  "bad or missing filter",
  "bad or missing extensions"
};

typedef struct ldapconninfo {
  LDAP *ld;
  Curl_recv *recv;  /* for stacking SSL handler */
  Curl_send *send;
  int proto;
  int msgid;
  bool ssldone;
  bool sslinst;
  bool didbind;
} ldapconninfo;

typedef struct ldapreqinfo {
  int msgid;
  int nument;
} ldapreqinfo;

static CURLcode ldap_setup_connection(struct connectdata *conn)
{
  ldapconninfo *li;
  LDAPURLDesc *lud;
  struct SessionHandle *data=conn->data;
  int rc, proto;
  CURLcode status;

  rc = ldap_url_parse(data->change.url, &lud);
  if(rc != LDAP_URL_SUCCESS) {
    const char *msg = "url parsing problem";
    status = CURLE_URL_MALFORMAT;
    if(rc > LDAP_URL_SUCCESS && rc <= LDAP_URL_ERR_BADEXTS) {
      if(rc == LDAP_URL_ERR_MEM)
        status = CURLE_OUT_OF_MEMORY;
      msg = url_errs[rc];
    }
    failf(conn->data, "LDAP local: %s", msg);
    return status;
  }
  proto = ldap_pvt_url_scheme2proto(lud->lud_scheme);
  ldap_free_urldesc(lud);

  li = calloc(1, sizeof(ldapconninfo));
  if(!li)
    return CURLE_OUT_OF_MEMORY;
  li->proto = proto;
  conn->proto.generic = li;
  connkeep(conn, "OpenLDAP default");
  /* TODO:
   * - provide option to choose SASL Binds instead of Simple
   */
  return CURLE_OK;
}

#ifdef USE_SSL
static Sockbuf_IO ldapsb_tls;
#endif

static CURLcode ldap_connect(struct connectdata *conn, bool *done)
{
  ldapconninfo *li = conn->proto.generic;
  struct SessionHandle *data = conn->data;
  int rc, proto = LDAP_VERSION3;
  char hosturl[1024];
  char *ptr;

  (void)done;

  strcpy(hosturl, "ldap");
  ptr = hosturl+4;
  if(conn->handler->flags & PROTOPT_SSL)
    *ptr++ = 's';
  snprintf(ptr, sizeof(hosturl)-(ptr-hosturl), "://%s:%d",
    conn->host.name, conn->remote_port);

  rc = ldap_init_fd(conn->sock[FIRSTSOCKET], li->proto, hosturl, &li->ld);
  if(rc) {
    failf(data, "LDAP local: Cannot connect to %s, %s",
          hosturl, ldap_err2string(rc));
    return CURLE_COULDNT_CONNECT;
  }

  ldap_set_option(li->ld, LDAP_OPT_PROTOCOL_VERSION, &proto);

#ifdef USE_SSL
  if(conn->handler->flags & PROTOPT_SSL) {
    CURLcode result;
    result = Curl_ssl_connect_nonblocking(conn, FIRSTSOCKET, &li->ssldone);
    if(result)
      return result;
  }
#endif

  return CURLE_OK;
}

static CURLcode ldap_connecting(struct connectdata *conn, bool *done)
{
  ldapconninfo *li = conn->proto.generic;
  struct SessionHandle *data = conn->data;
  LDAPMessage *msg = NULL;
  struct timeval tv = {0,1}, *tvp;
  int rc, err;
  char *info = NULL;

#ifdef USE_SSL
  if(conn->handler->flags & PROTOPT_SSL) {
    /* Is the SSL handshake complete yet? */
    if(!li->ssldone) {
      CURLcode result = Curl_ssl_connect_nonblocking(conn, FIRSTSOCKET,
                                                     &li->ssldone);
      if(result || !li->ssldone)
        return result;
    }

    /* Have we installed the libcurl SSL handlers into the sockbuf yet? */
    if(!li->sslinst) {
      Sockbuf *sb;
      ldap_get_option(li->ld, LDAP_OPT_SOCKBUF, &sb);
      ber_sockbuf_add_io(sb, &ldapsb_tls, LBER_SBIOD_LEVEL_TRANSPORT, conn);
      li->sslinst = TRUE;
      li->recv = conn->recv[FIRSTSOCKET];
      li->send = conn->send[FIRSTSOCKET];
    }
  }
#endif

  tvp = &tv;

retry:
  if(!li->didbind) {
    char *binddn;
    struct berval passwd;

    if(conn->bits.user_passwd) {
      binddn = conn->user;
      passwd.bv_val = conn->passwd;
      passwd.bv_len = strlen(passwd.bv_val);
    }
    else {
      binddn = NULL;
      passwd.bv_val = NULL;
      passwd.bv_len = 0;
    }
    rc = ldap_sasl_bind(li->ld, binddn, LDAP_SASL_SIMPLE, &passwd,
                        NULL, NULL, &li->msgid);
    if(rc)
      return CURLE_LDAP_CANNOT_BIND;
    li->didbind = TRUE;
    if(tvp)
      return CURLE_OK;
  }

  rc = ldap_result(li->ld, li->msgid, LDAP_MSG_ONE, tvp, &msg);
  if(rc < 0) {
    failf(data, "LDAP local: bind ldap_result %s", ldap_err2string(rc));
    return CURLE_LDAP_CANNOT_BIND;
  }
  if(rc == 0) {
    /* timed out */
    return CURLE_OK;
  }

  rc = ldap_parse_result(li->ld, msg, &err, NULL, &info, NULL, NULL, 1);
  if(rc) {
    failf(data, "LDAP local: bind ldap_parse_result %s", ldap_err2string(rc));
    return CURLE_LDAP_CANNOT_BIND;
  }

  /* Try to fallback to LDAPv2? */
  if(err == LDAP_PROTOCOL_ERROR) {
    int proto;
    ldap_get_option(li->ld, LDAP_OPT_PROTOCOL_VERSION, &proto);
    if(proto == LDAP_VERSION3) {
      if(info) {
        ldap_memfree(info);
        info = NULL;
      }
      proto = LDAP_VERSION2;
      ldap_set_option(li->ld, LDAP_OPT_PROTOCOL_VERSION, &proto);
      li->didbind = FALSE;
      goto retry;
    }
  }

  if(err) {
    failf(data, "LDAP remote: bind failed %s %s", ldap_err2string(rc),
          info ? info : "");
    if(info)
      ldap_memfree(info);
    return CURLE_LOGIN_DENIED;
  }

  if(info)
    ldap_memfree(info);
  conn->recv[FIRSTSOCKET] = ldap_recv;
  *done = TRUE;

  return CURLE_OK;
}

static CURLcode ldap_disconnect(struct connectdata *conn, bool dead_connection)
{
  ldapconninfo *li = conn->proto.generic;
  (void) dead_connection;

  if(li) {
    if(li->ld) {
      ldap_unbind_ext(li->ld, NULL, NULL);
      li->ld = NULL;
    }
    conn->proto.generic = NULL;
    free(li);
  }
  return CURLE_OK;
}

static CURLcode ldap_do(struct connectdata *conn, bool *done)
{
  ldapconninfo *li = conn->proto.generic;
  ldapreqinfo *lr;
  CURLcode status = CURLE_OK;
  int rc = 0;
  LDAPURLDesc *ludp = NULL;
  int msgid;
  struct SessionHandle *data=conn->data;

  connkeep(conn, "OpenLDAP do");

  infof(data, "LDAP local: %s\n", data->change.url);

  rc = ldap_url_parse(data->change.url, &ludp);
  if(rc != LDAP_URL_SUCCESS) {
    const char *msg = "url parsing problem";
    status = CURLE_URL_MALFORMAT;
    if(rc > LDAP_URL_SUCCESS && rc <= LDAP_URL_ERR_BADEXTS) {
      if(rc == LDAP_URL_ERR_MEM)
        status = CURLE_OUT_OF_MEMORY;
      msg = url_errs[rc];
    }
    failf(conn->data, "LDAP local: %s", msg);
    return status;
  }

  rc = ldap_search_ext(li->ld, ludp->lud_dn, ludp->lud_scope,
                       ludp->lud_filter, ludp->lud_attrs, 0,
                       NULL, NULL, NULL, 0, &msgid);
  ldap_free_urldesc(ludp);
  if(rc != LDAP_SUCCESS) {
    failf(data, "LDAP local: ldap_search_ext %s", ldap_err2string(rc));
    return CURLE_LDAP_SEARCH_FAILED;
  }
  lr = calloc(1,sizeof(ldapreqinfo));
  if(!lr)
    return CURLE_OUT_OF_MEMORY;
  lr->msgid = msgid;
  data->req.protop = lr;
  Curl_setup_transfer(conn, FIRSTSOCKET, -1, FALSE, NULL, -1, NULL);
  *done = TRUE;
  return CURLE_OK;
}

static CURLcode ldap_done(struct connectdata *conn, CURLcode res,
                          bool premature)
{
  ldapreqinfo *lr = conn->data->req.protop;

  (void)res;
  (void)premature;

  if(lr) {
    /* if there was a search in progress, abandon it */
    if(lr->msgid) {
      ldapconninfo *li = conn->proto.generic;
      ldap_abandon_ext(li->ld, lr->msgid, NULL, NULL);
      lr->msgid = 0;
    }
    conn->data->req.protop = NULL;
    free(lr);
  }

  return CURLE_OK;
}

static ssize_t ldap_recv(struct connectdata *conn, int sockindex, char *buf,
                         size_t len, CURLcode *err)
{
  ldapconninfo *li = conn->proto.generic;
  struct SessionHandle *data = conn->data;
  ldapreqinfo *lr = data->req.protop;
  int rc, ret;
  LDAPMessage *msg = NULL;
  LDAPMessage *ent;
  BerElement *ber = NULL;
  struct timeval tv = {0,1};

  (void)len;
  (void)buf;
  (void)sockindex;

  rc = ldap_result(li->ld, lr->msgid, LDAP_MSG_RECEIVED, &tv, &msg);
  if(rc < 0) {
    failf(data, "LDAP local: search ldap_result %s", ldap_err2string(rc));
    *err = CURLE_RECV_ERROR;
    return -1;
  }

  *err = CURLE_AGAIN;
  ret = -1;

  /* timed out */
  if(!msg)
    return ret;

  for(ent = ldap_first_message(li->ld, msg); ent;
    ent = ldap_next_message(li->ld, ent)) {
    struct berval bv, *bvals, **bvp = &bvals;
    int binary = 0, msgtype;

    msgtype = ldap_msgtype(ent);
    if(msgtype == LDAP_RES_SEARCH_RESULT) {
      int code;
      char *info = NULL;
      rc = ldap_parse_result(li->ld, ent, &code, NULL, &info, NULL, NULL, 0);
      if(rc) {
        failf(data, "LDAP local: search ldap_parse_result %s",
              ldap_err2string(rc));
        *err = CURLE_LDAP_SEARCH_FAILED;
      }
      else if(code && code != LDAP_SIZELIMIT_EXCEEDED) {
        failf(data, "LDAP remote: search failed %s %s", ldap_err2string(rc),
              info ? info : "");
        *err = CURLE_LDAP_SEARCH_FAILED;
      }
      else {
        /* successful */
        if(code == LDAP_SIZELIMIT_EXCEEDED)
          infof(data, "There are more than %d entries\n", lr->nument);
        data->req.size = data->req.bytecount;
        *err = CURLE_OK;
        ret = 0;
      }
      lr->msgid = 0;
      ldap_memfree(info);
      break;
    }
    else if(msgtype != LDAP_RES_SEARCH_ENTRY)
      continue;

    lr->nument++;
    rc = ldap_get_dn_ber(li->ld, ent, &ber, &bv);
    if(rc < 0) {
      /* TODO: verify that this is really how this return code should be
         handled */
      *err = CURLE_RECV_ERROR;
      return -1;
    }
    *err = Curl_client_write(conn, CLIENTWRITE_BODY, (char *)"DN: ", 4);
    if(*err)
      return -1;

    *err = Curl_client_write(conn, CLIENTWRITE_BODY, (char *)bv.bv_val,
                             bv.bv_len);
    if(*err)
      return -1;

    *err = Curl_client_write(conn, CLIENTWRITE_BODY, (char *)"\n", 1);
    if(*err)
      return -1;
    data->req.bytecount += bv.bv_len + 5;

    for(rc = ldap_get_attribute_ber(li->ld, ent, ber, &bv, bvp);
      rc == LDAP_SUCCESS;
      rc = ldap_get_attribute_ber(li->ld, ent, ber, &bv, bvp)) {
      int i;

      if(bv.bv_val == NULL) break;

      if(bv.bv_len > 7 && !strncmp(bv.bv_val + bv.bv_len - 7, ";binary", 7))
        binary = 1;
      else
        binary = 0;

      for(i=0; bvals[i].bv_val != NULL; i++) {
        int binval = 0;
        *err = Curl_client_write(conn, CLIENTWRITE_BODY, (char *)"\t", 1);
        if(*err)
          return -1;

        *err = Curl_client_write(conn, CLIENTWRITE_BODY, (char *)bv.bv_val,
                                 bv.bv_len);
        if(*err)
          return -1;

        *err = Curl_client_write(conn, CLIENTWRITE_BODY, (char *)":", 1);
        if(*err)
          return -1;
        data->req.bytecount += bv.bv_len + 2;

        if(!binary) {
          /* check for leading or trailing whitespace */
          if(ISSPACE(bvals[i].bv_val[0]) ||
              ISSPACE(bvals[i].bv_val[bvals[i].bv_len-1]))
            binval = 1;
          else {
            /* check for unprintable characters */
            unsigned int j;
            for(j=0; j<bvals[i].bv_len; j++)
              if(!ISPRINT(bvals[i].bv_val[j])) {
                binval = 1;
                break;
              }
          }
        }
        if(binary || binval) {
          char *val_b64 = NULL;
          size_t val_b64_sz = 0;
          /* Binary value, encode to base64. */
          CURLcode error = Curl_base64_encode(data,
                                              bvals[i].bv_val,
                                              bvals[i].bv_len,
                                              &val_b64,
                                              &val_b64_sz);
          if(error) {
            ber_memfree(bvals);
            ber_free(ber, 0);
            ldap_msgfree(msg);
            *err = error;
            return -1;
          }
          *err = Curl_client_write(conn, CLIENTWRITE_BODY, (char *)": ", 2);
          if(*err)
            return -1;

          data->req.bytecount += 2;
          if(val_b64_sz > 0) {
            *err = Curl_client_write(conn, CLIENTWRITE_BODY, val_b64,
                                     val_b64_sz);
            if(*err)
              return -1;
            free(val_b64);
            data->req.bytecount += val_b64_sz;
          }
        }
        else {
          *err = Curl_client_write(conn, CLIENTWRITE_BODY, (char *)" ", 1);
          if(*err)
            return -1;

          *err = Curl_client_write(conn, CLIENTWRITE_BODY, bvals[i].bv_val,
                                   bvals[i].bv_len);
          if(*err)
            return -1;

          data->req.bytecount += bvals[i].bv_len + 1;
        }
        *err = Curl_client_write(conn, CLIENTWRITE_BODY, (char *)"\n", 0);
        if(*err)
          return -1;

        data->req.bytecount++;
      }
      ber_memfree(bvals);
      *err = Curl_client_write(conn, CLIENTWRITE_BODY, (char *)"\n", 0);
      if(*err)
        return -1;
      data->req.bytecount++;
    }
    *err = Curl_client_write(conn, CLIENTWRITE_BODY, (char *)"\n", 0);
    if(*err)
      return -1;
    data->req.bytecount++;
    ber_free(ber, 0);
  }
  ldap_msgfree(msg);
  return ret;
}

#ifdef USE_SSL
static int
ldapsb_tls_setup(Sockbuf_IO_Desc *sbiod, void *arg)
{
  sbiod->sbiod_pvt = arg;
  return 0;
}

static int
ldapsb_tls_remove(Sockbuf_IO_Desc *sbiod)
{
  sbiod->sbiod_pvt = NULL;
  return 0;
}

/* We don't need to do anything because libcurl does it already */
static int
ldapsb_tls_close(Sockbuf_IO_Desc *sbiod)
{
  (void)sbiod;
  return 0;
}

static int
ldapsb_tls_ctrl(Sockbuf_IO_Desc *sbiod, int opt, void *arg)
{
  (void)arg;
  if(opt == LBER_SB_OPT_DATA_READY) {
    struct connectdata *conn = sbiod->sbiod_pvt;
    return Curl_ssl_data_pending(conn, FIRSTSOCKET);
  }
  return 0;
}

static ber_slen_t
ldapsb_tls_read(Sockbuf_IO_Desc *sbiod, void *buf, ber_len_t len)
{
  struct connectdata *conn = sbiod->sbiod_pvt;
  ldapconninfo *li = conn->proto.generic;
  ber_slen_t ret;
  CURLcode err = CURLE_RECV_ERROR;

  ret = li->recv(conn, FIRSTSOCKET, buf, len, &err);
  if(ret < 0 && err == CURLE_AGAIN) {
    SET_SOCKERRNO(EWOULDBLOCK);
  }
  return ret;
}

static ber_slen_t
ldapsb_tls_write(Sockbuf_IO_Desc *sbiod, void *buf, ber_len_t len)
{
  struct connectdata *conn = sbiod->sbiod_pvt;
  ldapconninfo *li = conn->proto.generic;
  ber_slen_t ret;
  CURLcode err = CURLE_SEND_ERROR;

  ret = li->send(conn, FIRSTSOCKET, buf, len, &err);
  if(ret < 0 && err == CURLE_AGAIN) {
    SET_SOCKERRNO(EWOULDBLOCK);
  }
  return ret;
}

static Sockbuf_IO ldapsb_tls =
{
  ldapsb_tls_setup,
  ldapsb_tls_remove,
  ldapsb_tls_ctrl,
  ldapsb_tls_read,
  ldapsb_tls_write,
  ldapsb_tls_close
};
#endif /* USE_SSL */

#endif /* !CURL_DISABLE_LDAP && USE_OPENLDAP */
