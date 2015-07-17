#ifndef HEADER_CURL_TOOL_CFGABLE_H
#define HEADER_CURL_TOOL_CFGABLE_H
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

#include "tool_sdecls.h"

#include "tool_metalink.h"

struct GlobalConfig;

struct OperationConfig {
  CURL *easy;               /* A copy of the handle from GlobalConfig */
  bool remote_time;
  char *random_file;
  char *egd_file;
  char *useragent;
  char *cookie;             /* single line with specified cookies */
  char *cookiejar;          /* write to this file */
  char *cookiefile;         /* read from this file */
  bool cookiesession;       /* new session? */
  bool encoding;            /* Accept-Encoding please */
  bool tr_encoding;         /* Transfer-Encoding please */
  unsigned long authtype;   /* auth bitmask */
  bool use_resume;
  bool resume_from_current;
  bool disable_epsv;
  bool disable_eprt;
  bool ftp_pret;
  long proto;
  bool proto_present;
  long proto_redir;
  bool proto_redir_present;
  curl_off_t resume_from;
  char *postfields;
  curl_off_t postfieldsize;
  char *referer;
  double timeout;
  double connecttimeout;
  long maxredirs;
  curl_off_t max_filesize;
  char *headerfile;
  char *ftpport;
  char *iface;
  int localport;
  int localportrange;
  unsigned short porttouse;
  char *range;
  long low_speed_limit;
  long low_speed_time;
  char *dns_servers;   /* dot notation: 1.1.1.1;2.2.2.2 */
  char *dns_interface; /* interface name */
  char *dns_ipv4_addr; /* dot notation */
  char *dns_ipv6_addr; /* dot notation */
  char *userpwd;
  char *login_options;
  char *tls_username;
  char *tls_password;
  char *tls_authtype;
  char *proxyuserpwd;
  char *proxy;
  int proxyver;             /* set to CURLPROXY_HTTP* define */
  char *noproxy;
  char *mail_from;
  struct curl_slist *mail_rcpt;
  char *mail_auth;
  bool sasl_ir;             /* Enable/disable SASL initial response */
  bool proxytunnel;
  bool ftp_append;          /* APPE on ftp */
  bool use_ascii;           /* select ascii or text transfer */
  bool autoreferer;         /* automatically set referer */
  bool failonerror;         /* fail on (HTTP) errors */
  bool include_headers;     /* send headers to data output */
  bool no_body;             /* don't get the body */
  bool dirlistonly;         /* only get the FTP dir list */
  bool followlocation;      /* follow http redirects */
  bool unrestricted_auth;   /* Continue to send authentication (user+password)
                               when following ocations, even when hostname
                               changed */
  bool netrc_opt;
  bool netrc;
  char *netrc_file;
  struct getout *url_list;  /* point to the first node */
  struct getout *url_last;  /* point to the last/current node */
  struct getout *url_get;   /* point to the node to fill in URL */
  struct getout *url_out;   /* point to the node to fill in outfile */
  char *cipher_list;
  char *cert;
  char *cert_type;
  char *cacert;
  char *capath;
  char *crlfile;
  char *pinnedpubkey;
  char *key;
  char *key_type;
  char *key_passwd;
  char *pubkey;
  char *hostpubmd5;
  char *engine;
  bool crlf;
  char *customrequest;
  char *krblevel;
  long httpversion;
  bool nobuffer;
  bool readbusy;            /* set when reading input returns EAGAIN */
  bool globoff;
  bool use_httpget;
  bool insecure_ok;         /* set TRUE to allow insecure SSL connects */
  bool verifystatus;
  bool create_dirs;
  bool ftp_create_dirs;
  bool ftp_skip_ip;
  bool proxynegotiate;
  bool proxyntlm;
  bool proxydigest;
  bool proxybasic;
  bool proxyanyauth;
  char *writeout;           /* %-styled format string to output */
  bool writeenv;            /* write results to environment, if available */
  struct curl_slist *quote;
  struct curl_slist *postquote;
  struct curl_slist *prequote;
  long ssl_version;
  long ip_version;
  curl_TimeCond timecond;
  time_t condtime;
  struct curl_slist *headers;
  struct curl_slist *proxyheaders;
  struct curl_httppost *httppost;
  struct curl_httppost *last_post;
  struct curl_slist *telnet_options;
  struct curl_slist *resolve;
  HttpReq httpreq;

  /* for bandwidth limiting features: */
  curl_off_t sendpersecond; /* send to peer */
  curl_off_t recvpersecond; /* receive from peer */

  bool ftp_ssl;
  bool ftp_ssl_reqd;
  bool ftp_ssl_control;
  bool ftp_ssl_ccc;
  int ftp_ssl_ccc_mode;

  char *socksproxy;         /* set to server string */
  int socksver;             /* set to CURLPROXY_SOCKS* define */
  char *socks5_gssapi_service;  /* set service name for gssapi principal
                                 * default rcmd */
  char *proxy_service_name; /* set service name for proxy negotiation
                             * default HTTP */
  int socks5_gssapi_nec ;   /* The NEC reference server does not protect
                             * the encryption type exchange */
  char *service_name;       /* set negotiation service name
                             * default HTTP */

  bool tcp_nodelay;
  long req_retry;           /* number of retries */
  long retry_delay;         /* delay between retries (in seconds) */
  long retry_maxtime;       /* maximum time to keep retrying */

  char *ftp_account;        /* for ACCT */
  char *ftp_alternative_to_user;  /* send command if USER/PASS fails */
  int ftp_filemethod;
  long tftp_blksize;        /* TFTP BLKSIZE option */
  bool ignorecl;            /* --ignore-content-length */
  bool disable_sessionid;

  bool raw;
  bool post301;
  bool post302;
  bool post303;
  bool nokeepalive;         /* for keepalive needs */
  long alivetime;
  bool content_disposition; /* use Content-disposition filename */

  int default_node_flags;   /* default flags to search for each 'node', which
                               is basically each given URL to transfer */

  bool xattr;               /* store metadata in extended attributes */
  long gssapi_delegation;
  bool ssl_allow_beast;     /* allow this SSL vulnerability */
  bool ssl_no_revoke;       /* disable SSL certificate revocation checks */

  bool use_metalink;        /* process given URLs as metalink XML file */
  metalinkfile *metalinkfile_list; /* point to the first node */
  metalinkfile *metalinkfile_last; /* point to the last/current node */
#ifdef CURLDEBUG
  bool test_event_based;
#endif
  char *xoauth2_bearer;           /* XOAUTH2 bearer token */
  bool nonpn;                     /* enable/disable TLS NPN extension */
  bool noalpn;                    /* enable/disable TLS ALPN extension */
  char *unix_socket_path;         /* path to Unix domain socket */
  bool falsestart;
  bool path_as_is;
  struct GlobalConfig *global;
  struct OperationConfig *prev;
  struct OperationConfig *next;   /* Always last in the struct */
};

struct GlobalConfig {
  CURL *easy;                     /* Once we have one, we keep it here */
  int showerror;                  /* -1 == unset, default => show errors
                                      0 => -s is used to NOT show errors
                                      1 => -S has been used to show errors */
  bool mute;                      /* don't show messages, --silent given */
  bool noprogress;                /* don't show progress bar --silent given */
  bool isatty;                    /* Updated internally if output is a tty */
  FILE *errors;                   /* Error stream, defaults to stderr */
  bool errors_fopened;            /* Whether error stream isn't stderr */
  char *trace_dump;               /* file to dump the network trace to */
  FILE *trace_stream;
  bool trace_fopened;
  trace tracetype;
  bool tracetime;                 /* include timestamp? */
  int progressmode;               /* CURL_PROGRESS_BAR / CURL_PROGRESS_STATS */
  char *libcurl;                  /* Output libcurl code to this file name */

  struct OperationConfig *first;
  struct OperationConfig *current;
  struct OperationConfig *last;   /* Always last in the struct */
};

void config_init(struct OperationConfig *config);
void config_free(struct OperationConfig *config);

#endif /* HEADER_CURL_TOOL_CFGABLE_H */
