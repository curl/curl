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
#include <curlx.h>
#include <memdebug.h> /* keep this as LAST include */

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

  tool_safefree(config->useragent);
  tool_safefree(config->altsvc);
  tool_safefree(config->hsts);
  tool_safefree(config->haproxy_clientip);
  curl_slist_free_all(config->cookies);
  tool_safefree(config->cookiejar);
  curl_slist_free_all(config->cookiefiles);

  curlx_dyn_free(&config->postdata);
  tool_safefree(config->query);
  tool_safefree(config->referer);

  tool_safefree(config->headerfile);
  tool_safefree(config->ftpport);
  tool_safefree(config->iface);

  tool_safefree(config->range);

  tool_safefree(config->userpwd);
  tool_safefree(config->tls_username);
  tool_safefree(config->tls_password);
  tool_safefree(config->tls_authtype);
  tool_safefree(config->proxy_tls_username);
  tool_safefree(config->proxy_tls_password);
  tool_safefree(config->proxy_tls_authtype);
  tool_safefree(config->proxyuserpwd);
  tool_safefree(config->proxy);

  tool_safefree(config->dns_ipv6_addr);
  tool_safefree(config->dns_ipv4_addr);
  tool_safefree(config->dns_interface);
  tool_safefree(config->dns_servers);

  tool_safefree(config->noproxy);

  tool_safefree(config->mail_from);
  curl_slist_free_all(config->mail_rcpt);
  tool_safefree(config->mail_auth);

  tool_safefree(config->netrc_file);
  tool_safefree(config->output_dir);
  tool_safefree(config->proto_str);
  tool_safefree(config->proto_redir_str);

  urlnode = config->url_list;
  while(urlnode) {
    struct getout *next = urlnode->next;
    tool_safefree(urlnode->url);
    tool_safefree(urlnode->outfile);
    tool_safefree(urlnode->infile);
    tool_safefree(urlnode);
    urlnode = next;
  }
  config->url_list = NULL;
  config->url_last = NULL;
  config->url_get = NULL;
  config->url_out = NULL;

#ifndef CURL_DISABLE_IPFS
  tool_safefree(config->ipfs_gateway);
#endif /* !CURL_DISABLE_IPFS */
  tool_safefree(config->doh_url);
  tool_safefree(config->cipher_list);
  tool_safefree(config->proxy_cipher_list);
  tool_safefree(config->cipher13_list);
  tool_safefree(config->proxy_cipher13_list);
  tool_safefree(config->cert);
  tool_safefree(config->proxy_cert);
  tool_safefree(config->cert_type);
  tool_safefree(config->proxy_cert_type);
  tool_safefree(config->cacert);
  tool_safefree(config->login_options);
  tool_safefree(config->proxy_cacert);
  tool_safefree(config->capath);
  tool_safefree(config->proxy_capath);
  tool_safefree(config->crlfile);
  tool_safefree(config->pinnedpubkey);
  tool_safefree(config->proxy_pinnedpubkey);
  tool_safefree(config->proxy_crlfile);
  tool_safefree(config->key);
  tool_safefree(config->proxy_key);
  tool_safefree(config->key_type);
  tool_safefree(config->proxy_key_type);
  tool_safefree(config->key_passwd);
  tool_safefree(config->proxy_key_passwd);
  tool_safefree(config->pubkey);
  tool_safefree(config->hostpubmd5);
  tool_safefree(config->hostpubsha256);
  tool_safefree(config->engine);
  tool_safefree(config->etag_save_file);
  tool_safefree(config->etag_compare_file);
  tool_safefree(config->ssl_ec_curves);
  tool_safefree(config->request_target);
  tool_safefree(config->customrequest);
  tool_safefree(config->krblevel);
  tool_safefree(config->oauth_bearer);
  tool_safefree(config->sasl_authzid);
  tool_safefree(config->unix_socket_path);
  tool_safefree(config->writeout);
  tool_safefree(config->proto_default);

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

  tool_safefree(config->preproxy);
  tool_safefree(config->proxy_service_name);
  tool_safefree(config->service_name);
  tool_safefree(config->ftp_account);
  tool_safefree(config->ftp_alternative_to_user);
  tool_safefree(config->aws_sigv4);
  tool_safefree(config->proto_str);
  tool_safefree(config->proto_redir_str);
  tool_safefree(config->ech);
  tool_safefree(config->ech_config);
  tool_safefree(config->ech_public);
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
