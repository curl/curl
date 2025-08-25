#ifndef HEADER_CURL_TOOL_CFGABLE_H
#define HEADER_CURL_TOOL_CFGABLE_H
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

#include <curl/mprintf.h>
#include "tool_setup.h"
#include "tool_sdecls.h"
#include "tool_urlglob.h"
#include "var.h"

/* the type we use for storing a single boolean bit */
#ifndef BIT
#ifdef _MSC_VER
#define BIT(x) bool x
#else
#define BIT(x) unsigned int x:1
#endif
#endif

/* make the tool use the libcurl *printf family */
# undef printf
# undef fprintf
# undef msnprintf
# undef vprintf
# undef vfprintf
# undef mvsnprintf
# undef aprintf
# undef vaprintf
# define printf curl_mprintf
# define fprintf curl_mfprintf
# define msnprintf curl_msnprintf
# define vprintf curl_mvprintf
# define vfprintf curl_mvfprintf
# define mvsnprintf curl_mvsnprintf
# define aprintf curl_maprintf
# define vaprintf curl_mvaprintf

#define checkprefix(a,b)    curl_strnequal(b, STRCONST(a))

#define tool_safefree(ptr)                      \
  do { free((ptr)); (ptr) = NULL;} while(0)

extern struct GlobalConfig *global;

struct State {
  struct getout *urlnode;
  struct URLGlob inglob;
  struct URLGlob urlglob;
  char *httpgetfields;
  char *uploadfile;
  curl_off_t upnum;     /* number of files to upload */
  curl_off_t upidx;     /* index for upload glob */
  curl_off_t urlnum;    /* how many iterations this URL has with ranges etc */
  curl_off_t urlidx;    /* index for globbed URLs */
};

struct OperationConfig {
  struct dynbuf postdata;
  char *useragent;
  struct curl_slist *cookies;  /* cookies to serialize into a single line */
  char *cookiejar;          /* write to this file */
  struct curl_slist *cookiefiles;  /* file(s) to load cookies from */
  char *altsvc;             /* alt-svc cache filename */
  char *hsts;               /* HSTS cache filename */
  char *proto_str;
  char *proto_redir_str;
  char *proto_default;
  curl_off_t resume_from;
  char *postfields;
  char *referer;
  char *query;
  curl_off_t max_filesize;
  char *output_dir;
  char *headerfile;
  char *ftpport;
  char *iface;
  char *range;
  char *dns_servers;   /* dot notation: 1.1.1.1;2.2.2.2 */
  char *dns_interface; /* interface name */
  char *dns_ipv4_addr; /* dot notation */
  char *dns_ipv6_addr; /* dot notation */
  char *userpwd;
  char *login_options;
  char *tls_username;
  char *tls_password;
  char *tls_authtype;
  char *proxy_tls_username;
  char *proxy_tls_password;
  char *proxy_tls_authtype;
  char *proxyuserpwd;
  char *proxy;
  char *noproxy;
  char *mail_from;
  struct curl_slist *mail_rcpt;
  char *mail_auth;
  char *sasl_authzid;       /* Authorization identity (identity to use) */
  char *netrc_file;
  struct getout *url_list;  /* point to the first node */
  struct getout *url_last;  /* point to the last/current node */
  struct getout *url_get;   /* point to the node to fill in URL */
  struct getout *url_out;   /* point to the node to fill in outfile */
  struct getout *url_ul;    /* point to the node to fill in upload */
  size_t num_urls;          /* number of URLs added to the list */
#ifndef CURL_DISABLE_IPFS
  char *ipfs_gateway;
#endif /* !CURL_DISABLE_IPFS */
  char *doh_url;
  char *cipher_list;
  char *proxy_cipher_list;
  char *cipher13_list;
  char *proxy_cipher13_list;
  char *cert;
  char *proxy_cert;
  char *cert_type;
  char *proxy_cert_type;
  char *cacert;
  char *proxy_cacert;
  char *capath;
  char *proxy_capath;
  char *crlfile;
  char *proxy_crlfile;
  char *pinnedpubkey;
  char *proxy_pinnedpubkey;
  char *key;
  char *proxy_key;
  char *key_type;
  char *proxy_key_type;
  char *key_passwd;
  char *proxy_key_passwd;
  char *pubkey;
  char *hostpubmd5;
  char *hostpubsha256;
  char *engine;
  char *etag_save_file;
  char *etag_compare_file;
  char *customrequest;
  char *ssl_ec_curves;
  char *ssl_signature_algorithms;
  char *krblevel;
  char *request_target;
  char *writeout;           /* %-styled format string to output */
  struct curl_slist *quote;
  struct curl_slist *postquote;
  struct curl_slist *prequote;
  struct curl_slist *headers;
  struct curl_slist *proxyheaders;
  struct tool_mime *mimeroot;
  struct tool_mime *mimecurrent;
  curl_mime *mimepost;
  struct curl_slist *telnet_options;
  struct curl_slist *resolve;
  struct curl_slist *connect_to;
  char *preproxy;
  char *proxy_service_name; /* set authentication service name for HTTP and
                               SOCKS5 proxies */
  char *service_name;       /* set authentication service name for DIGEST-MD5,
                               Kerberos 5 and SPNEGO */
  char *ftp_account;        /* for ACCT */
  char *ftp_alternative_to_user;  /* send command if USER/PASS fails */
  char *oauth_bearer;             /* OAuth 2.0 bearer token */
  char *unix_socket_path;         /* path to Unix domain socket */
  char *haproxy_clientip;         /* client IP for HAProxy protocol */
  char *aws_sigv4;
  char *ech;                      /* Config set by --ech keywords */
  char *ech_config;               /* Config set by "--ech esl:" option */
  char *ech_public;               /* Config set by "--ech pn:" option */
  struct OperationConfig *prev;
  struct OperationConfig *next;   /* Always last in the struct */
  curl_off_t condtime;
  /* for bandwidth limiting features: */
  curl_off_t sendpersecond; /* send to peer */
  curl_off_t recvpersecond; /* receive from peer */

  long proxy_ssl_version;
  long ip_version;
  long create_file_mode; /* CURLOPT_NEW_FILE_PERMS */
  long low_speed_limit;
  long low_speed_time;
  long ip_tos;         /* IP Type of Service */
  long vlan_priority;  /* VLAN priority */
  long localport;
  long localportrange;
  unsigned long authtype;   /* auth bitmask */
  long timeout_ms;
  long connecttimeout_ms;
  long maxredirs;
  long httpversion;
  unsigned long socks5_auth;/* auth bitmask for socks5 proxies */
  long req_retry;           /* number of retries */
  long retry_delay_ms;      /* delay between retries (in milliseconds) */
  long retry_maxtime_ms;    /* maximum time to keep retrying */

  unsigned long mime_options; /* Mime option flags. */
  long tftp_blksize;        /* TFTP BLKSIZE option */
  long alivetime;           /* keepalive-time */
  long alivecnt;            /* keepalive-cnt */
  long gssapi_delegation;
  long expect100timeout_ms;
  long happy_eyeballs_timeout_ms; /* happy eyeballs timeout in milliseconds.
                                     0 is valid. default: CURL_HET_DEFAULT. */
  unsigned long timecond;
  long followlocation;      /* follow http redirects mode */
  HttpReq httpreq;
  long proxyver;             /* set to CURLPROXY_HTTP* define */
  long ftp_ssl_ccc_mode;
  long ftp_filemethod;
  enum {
    CLOBBER_DEFAULT, /* Provides compatibility with previous versions of curl,
                        by using the default behavior for -o, -O, and -J.
                        If those options would have overwritten files, like
                        -o and -O would, then overwrite them. In the case of
                        -J, this will not overwrite any files. */
    CLOBBER_NEVER, /* If the file exists, always fail */
    CLOBBER_ALWAYS /* If the file exists, always overwrite it */
  } file_clobber_mode;
  unsigned char upload_flags; /* Bitmask for --upload-flags */
  unsigned short porttouse;
  unsigned char ssl_version;     /* 0 - 4, 0 being default */
  unsigned char ssl_version_max; /* 0 - 4, 0 being default */
  BIT(remote_name_all);   /* --remote-name-all */
  BIT(remote_time);
  BIT(cookiesession);       /* new session? */
  BIT(encoding);            /* Accept-Encoding please */
  BIT(tr_encoding);         /* Transfer-Encoding please */
  BIT(use_resume);
  BIT(resume_from_current);
  BIT(disable_epsv);
  BIT(disable_eprt);
  BIT(ftp_pret);
  BIT(proto_present);
  BIT(proto_redir_present);
  BIT(mail_rcpt_allowfails); /* --mail-rcpt-allowfails */
  BIT(sasl_ir);             /* Enable/disable SASL initial response */
  BIT(proxytunnel);
  BIT(ftp_append);          /* APPE on ftp */
  BIT(use_ascii);           /* select ASCII or text transfer */
  BIT(autoreferer);         /* automatically set referer */
  BIT(failonerror);         /* fail on (HTTP) errors */
  BIT(failwithbody);        /* fail on (HTTP) errors but still store body */
  BIT(show_headers);        /* show headers to data output */
  BIT(no_body);             /* do not get the body */
  BIT(dirlistonly);         /* only get the FTP dir list */
  BIT(unrestricted_auth);   /* Continue to send authentication (user+password)
                               when following redirects, even when hostname
                               changed */
  BIT(netrc_opt);
  BIT(netrc);
  BIT(crlf);
  BIT(http09_allowed);
  BIT(nobuffer);
  BIT(readbusy);            /* set when reading input returns EAGAIN */
  BIT(globoff);
  BIT(use_httpget);
  BIT(insecure_ok);         /* set TRUE to allow insecure SSL connects */
  BIT(doh_insecure_ok);     /* set TRUE to allow insecure SSL connects
                               for DoH */
  BIT(proxy_insecure_ok);   /* set TRUE to allow insecure SSL connects
                               for proxy */
  BIT(terminal_binary_ok);
  BIT(verifystatus);
  BIT(doh_verifystatus);
  BIT(create_dirs);
  BIT(ftp_create_dirs);
  BIT(ftp_skip_ip);
  BIT(proxynegotiate);
  BIT(proxyntlm);
  BIT(proxydigest);
  BIT(proxybasic);
  BIT(proxyanyauth);
  BIT(jsoned); /* added json content-type */
  BIT(ftp_ssl);
  BIT(ftp_ssl_reqd);
  BIT(ftp_ssl_control);
  BIT(ftp_ssl_ccc);
  BIT(socks5_gssapi_nec);   /* The NEC reference server does not protect the
                               encryption type exchange */
  BIT(tcp_nodelay);
  BIT(tcp_fastopen);
  BIT(retry_all_errors);    /* retry on any error */
  BIT(retry_connrefused);   /* set connection refused as a transient error */
  BIT(tftp_no_options);     /* do not send TFTP options requests */
  BIT(ignorecl);            /* --ignore-content-length */
  BIT(disable_sessionid);

  BIT(raw);
  BIT(post301);
  BIT(post302);
  BIT(post303);
  BIT(nokeepalive);         /* for keepalive needs */
  BIT(content_disposition); /* use Content-disposition filename */

  BIT(xattr);               /* store metadata in extended attributes */
  BIT(ssl_allow_beast);     /* allow this SSL vulnerability */
  BIT(ssl_allow_earlydata); /* allow use of TLSv1.3 early data */
  BIT(proxy_ssl_allow_beast); /* allow this SSL vulnerability for proxy */
  BIT(ssl_no_revoke);       /* disable SSL certificate revocation checks */
  BIT(ssl_revoke_best_effort); /* ignore SSL revocation offline/missing
                                  revocation list errors */

  BIT(native_ca_store);        /* use the native OS CA store */
  BIT(proxy_native_ca_store);  /* use the native OS CA store for proxy */
  BIT(ssl_auto_client_cert);   /* automatically locate and use a client
                                  certificate for authentication (Schannel) */
  BIT(proxy_ssl_auto_client_cert); /* proxy version of ssl_auto_client_cert */
  BIT(noalpn);                    /* enable/disable TLS ALPN extension */
  BIT(abstract_unix_socket);      /* path to an abstract Unix domain socket */
  BIT(path_as_is);
  BIT(suppress_connect_headers);  /* suppress proxy CONNECT response headers
                                     from user callbacks */
  BIT(synthetic_error);           /* if TRUE, this is tool-internal error */
  BIT(ssh_compression);           /* enable/disable SSH compression */
  BIT(haproxy_protocol);          /* whether to send HAProxy protocol v1 */
  BIT(disallow_username_in_url);  /* disallow usernames in URLs */
  BIT(mptcp);                     /* enable MPTCP support */
  BIT(rm_partial);                /* on error, remove partially written output
                                     files */
  BIT(skip_existing);
};

#if defined(_WIN32) && !defined(UNDER_CE)
struct termout {
  wchar_t *buf;
  DWORD len;
};
#endif

struct GlobalConfig {
  struct State state;             /* for create_transfer() */
  char *trace_dump;               /* file to dump the network trace to */
  FILE *trace_stream;
  char *libcurl;                  /* Output libcurl code to this filename */
  char *ssl_sessions;             /* file to load/save SSL session tickets */
  char *knownhosts;               /* known host path, if set. curl_free()
                                     this */
  struct tool_var *variables;
  struct OperationConfig *first;
  struct OperationConfig *current;
  struct OperationConfig *last;
#if defined(_WIN32) && !defined(UNDER_CE)
  struct termout term;
#endif
  timediff_t ms_per_transfer;     /* start next transfer after (at least) this
                                     many milliseconds */
  trace tracetype;
  int progressmode;               /* CURL_PROGRESS_BAR / CURL_PROGRESS_STATS */
  unsigned short parallel_host; /* MAX_PARALLEL_HOST is the maximum */
  unsigned short parallel_max; /* MAX_PARALLEL is the maximum */
  unsigned char verbosity;        /* How verbose we should be */
#ifdef DEBUGBUILD
  BIT(test_duphandle);
  BIT(test_event_based);
#endif
  BIT(parallel);
  BIT(parallel_connect);
  BIT(fail_early);                /* exit on first transfer error */
  BIT(styled_output);             /* enable fancy output style detection */
  BIT(trace_fopened);
  BIT(tracetime);                 /* include timestamp? */
  BIT(traceids);                  /* include xfer-/conn-id? */
  BIT(showerror);                 /* show errors when silent */
  BIT(silent);                    /* do not show messages, --silent given */
  BIT(noprogress);                /* do not show progress bar */
  BIT(isatty);                    /* Updated internally if output is a tty */
  BIT(trace_set);                 /* --trace-config has been used */
};

struct OperationConfig *config_alloc(void);
void config_free(struct OperationConfig *config);
CURLcode globalconf_init(void);
void globalconf_free(void);

#endif /* HEADER_CURL_TOOL_CFGABLE_H */
