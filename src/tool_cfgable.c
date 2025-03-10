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

#include "tool_cfgable.h"
#include "tool_formparse.h"
#include "tool_paramhlp.h"
#include "tool_main.h"
#include "curlx.h"

#include "memdebug.h" /* keep this as LAST include */

void config_init(struct OperationConfig *config)
{
  memset(config, 0, sizeof(struct OperationConfig));

  config->use_httpget = FALSE;
  config->create_dirs = FALSE;
  config->maxredirs = DEFAULT_MAXREDIRS;
  config->proto_present = FALSE;
  config->proto_redir_present = FALSE;
  config->proto_default = NULL;
  config->tcp_nodelay = TRUE; /* enabled by default */
  config->happy_eyeballs_timeout_ms = CURL_HET_DEFAULT;
  config->http09_allowed = FALSE;
  config->ftp_skip_ip = TRUE;
  config->file_clobber_mode = CLOBBER_DEFAULT;
  config->upload_flags = CURLULFLAG_SEEN;
  curlx_dyn_init(&config->postdata, MAX_FILE2MEMORY);
}

static void free_config_fields(struct OperationConfig *config)
{
  struct getout *urlnode;

  curlx_safefree(config->useragent);
  curlx_safefree(config->altsvc);
  curlx_safefree(config->hsts);
  curlx_safefree(config->haproxy_clientip);
  curl_slist_free_all(config->cookies);
  curlx_safefree(config->cookiejar);
  curl_slist_free_all(config->cookiefiles);

  curlx_dyn_free(&config->postdata);
  curlx_safefree(config->query);
  curlx_safefree(config->referer);

  curlx_safefree(config->headerfile);
  curlx_safefree(config->ftpport);
  curlx_safefree(config->iface);

  curlx_safefree(config->range);

  curlx_safefree(config->userpwd);
  curlx_safefree(config->tls_username);
  curlx_safefree(config->tls_password);
  curlx_safefree(config->tls_authtype);
  curlx_safefree(config->proxy_tls_username);
  curlx_safefree(config->proxy_tls_password);
  curlx_safefree(config->proxy_tls_authtype);
  curlx_safefree(config->proxyuserpwd);
  curlx_safefree(config->proxy);

  curlx_safefree(config->dns_ipv6_addr);
  curlx_safefree(config->dns_ipv4_addr);
  curlx_safefree(config->dns_interface);
  curlx_safefree(config->dns_servers);

  curlx_safefree(config->noproxy);

  curlx_safefree(config->mail_from);
  curl_slist_free_all(config->mail_rcpt);
  curlx_safefree(config->mail_auth);

  curlx_safefree(config->netrc_file);
  curlx_safefree(config->output_dir);
  curlx_safefree(config->proto_str);
  curlx_safefree(config->proto_redir_str);

  urlnode = config->url_list;
  while(urlnode) {
    struct getout *next = urlnode->next;
    curlx_safefree(urlnode->url);
    curlx_safefree(urlnode->outfile);
    curlx_safefree(urlnode->infile);
    curlx_safefree(urlnode);
    urlnode = next;
  }
  config->url_list = NULL;
  config->url_last = NULL;
  config->url_get = NULL;
  config->url_out = NULL;

#ifndef CURL_DISABLE_IPFS
  curlx_safefree(config->ipfs_gateway);
#endif /* !CURL_DISABLE_IPFS */
  curlx_safefree(config->doh_url);
  curlx_safefree(config->cipher_list);
  curlx_safefree(config->proxy_cipher_list);
  curlx_safefree(config->cipher13_list);
  curlx_safefree(config->proxy_cipher13_list);
  curlx_safefree(config->cert);
  curlx_safefree(config->proxy_cert);
  curlx_safefree(config->cert_type);
  curlx_safefree(config->proxy_cert_type);
  curlx_safefree(config->cacert);
  curlx_safefree(config->login_options);
  curlx_safefree(config->proxy_cacert);
  curlx_safefree(config->capath);
  curlx_safefree(config->proxy_capath);
  curlx_safefree(config->crlfile);
  curlx_safefree(config->pinnedpubkey);
  curlx_safefree(config->proxy_pinnedpubkey);
  curlx_safefree(config->proxy_crlfile);
  curlx_safefree(config->key);
  curlx_safefree(config->proxy_key);
  curlx_safefree(config->key_type);
  curlx_safefree(config->proxy_key_type);
  curlx_safefree(config->key_passwd);
  curlx_safefree(config->proxy_key_passwd);
  curlx_safefree(config->pubkey);
  curlx_safefree(config->hostpubmd5);
  curlx_safefree(config->hostpubsha256);
  curlx_safefree(config->engine);
  curlx_safefree(config->etag_save_file);
  curlx_safefree(config->etag_compare_file);
  curlx_safefree(config->ssl_ec_curves);
  curlx_safefree(config->request_target);
  curlx_safefree(config->customrequest);
  curlx_safefree(config->krblevel);
  curlx_safefree(config->oauth_bearer);
  curlx_safefree(config->sasl_authzid);
  curlx_safefree(config->unix_socket_path);
  curlx_safefree(config->writeout);
  curlx_safefree(config->proto_default);

  curl_slist_free_all(config->quote);
  curl_slist_free_all(config->postquote);
  curl_slist_free_all(config->prequote);

  curl_slist_free_all(config->headers);
  curl_slist_free_all(config->proxyheaders);

  curl_mime_free(config->mimepost);
  config->mimepost = NULL;
  tool_mime_free(config->mimeroot);
  config->mimeroot = NULL;
  config->mimecurrent = NULL;

  curl_slist_free_all(config->telnet_options);
  curl_slist_free_all(config->resolve);
  curl_slist_free_all(config->connect_to);

  curlx_safefree(config->preproxy);
  curlx_safefree(config->proxy_service_name);
  curlx_safefree(config->service_name);
  curlx_safefree(config->ftp_account);
  curlx_safefree(config->ftp_alternative_to_user);
  curlx_safefree(config->aws_sigv4);
  curlx_safefree(config->proto_str);
  curlx_safefree(config->proto_redir_str);
  curlx_safefree(config->ech);
  curlx_safefree(config->ech_config);
  curlx_safefree(config->ech_public);
}

void config_free(struct OperationConfig *config)
{
  struct OperationConfig *last = config;

  /* Free each of the structures in reverse order */
  while(last) {
    struct OperationConfig *prev = last->prev;

    free_config_fields(last);
    free(last);

    last = prev;
  }
}
