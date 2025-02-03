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
 * are also available at https://fetch.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 * SPDX-License-Identifier: fetch
 *
 ***************************************************************************/
#include "tool_setup.h"

#include "tool_cfgable.h"
#include "tool_formparse.h"
#include "tool_paramhlp.h"
#include "tool_main.h"

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
  config->happy_eyeballs_timeout_ms = FETCH_HET_DEFAULT;
  config->http09_allowed = FALSE;
  config->ftp_skip_ip = TRUE;
  config->file_clobber_mode = CLOBBER_DEFAULT;
  fetchx_dyn_init(&config->postdata, MAX_FILE2MEMORY);
}

static void free_config_fields(struct OperationConfig *config)
{
  struct getout *urlnode;

  Fetch_safefree(config->useragent);
  Fetch_safefree(config->altsvc);
  Fetch_safefree(config->hsts);
  Fetch_safefree(config->haproxy_clientip);
  fetch_slist_free_all(config->cookies);
  Fetch_safefree(config->cookiejar);
  fetch_slist_free_all(config->cookiefiles);

  Fetch_dyn_free(&config->postdata);
  Fetch_safefree(config->query);
  Fetch_safefree(config->referer);

  Fetch_safefree(config->headerfile);
  Fetch_safefree(config->ftpport);
  Fetch_safefree(config->iface);

  Fetch_safefree(config->range);

  Fetch_safefree(config->userpwd);
  Fetch_safefree(config->tls_username);
  Fetch_safefree(config->tls_password);
  Fetch_safefree(config->tls_authtype);
  Fetch_safefree(config->proxy_tls_username);
  Fetch_safefree(config->proxy_tls_password);
  Fetch_safefree(config->proxy_tls_authtype);
  Fetch_safefree(config->proxyuserpwd);
  Fetch_safefree(config->proxy);

  Fetch_safefree(config->dns_ipv6_addr);
  Fetch_safefree(config->dns_ipv4_addr);
  Fetch_safefree(config->dns_interface);
  Fetch_safefree(config->dns_servers);

  Fetch_safefree(config->noproxy);

  Fetch_safefree(config->mail_from);
  fetch_slist_free_all(config->mail_rcpt);
  Fetch_safefree(config->mail_auth);

  Fetch_safefree(config->netrc_file);
  Fetch_safefree(config->output_dir);
  Fetch_safefree(config->proto_str);
  Fetch_safefree(config->proto_redir_str);

  urlnode = config->url_list;
  while (urlnode)
  {
    struct getout *next = urlnode->next;
    Fetch_safefree(urlnode->url);
    Fetch_safefree(urlnode->outfile);
    Fetch_safefree(urlnode->infile);
    Fetch_safefree(urlnode);
    urlnode = next;
  }
  config->url_list = NULL;
  config->url_last = NULL;
  config->url_get = NULL;
  config->url_out = NULL;

#ifndef FETCH_DISABLE_IPFS
  Fetch_safefree(config->ipfs_gateway);
#endif /* !FETCH_DISABLE_IPFS */
  Fetch_safefree(config->doh_url);
  Fetch_safefree(config->cipher_list);
  Fetch_safefree(config->proxy_cipher_list);
  Fetch_safefree(config->cipher13_list);
  Fetch_safefree(config->proxy_cipher13_list);
  Fetch_safefree(config->cert);
  Fetch_safefree(config->proxy_cert);
  Fetch_safefree(config->cert_type);
  Fetch_safefree(config->proxy_cert_type);
  Fetch_safefree(config->cacert);
  Fetch_safefree(config->login_options);
  Fetch_safefree(config->proxy_cacert);
  Fetch_safefree(config->capath);
  Fetch_safefree(config->proxy_capath);
  Fetch_safefree(config->crlfile);
  Fetch_safefree(config->pinnedpubkey);
  Fetch_safefree(config->proxy_pinnedpubkey);
  Fetch_safefree(config->proxy_crlfile);
  Fetch_safefree(config->key);
  Fetch_safefree(config->proxy_key);
  Fetch_safefree(config->key_type);
  Fetch_safefree(config->proxy_key_type);
  Fetch_safefree(config->key_passwd);
  Fetch_safefree(config->proxy_key_passwd);
  Fetch_safefree(config->pubkey);
  Fetch_safefree(config->hostpubmd5);
  Fetch_safefree(config->hostpubsha256);
  Fetch_safefree(config->engine);
  Fetch_safefree(config->etag_save_file);
  Fetch_safefree(config->etag_compare_file);
  Fetch_safefree(config->ssl_ec_curves);
  Fetch_safefree(config->request_target);
  Fetch_safefree(config->customrequest);
  Fetch_safefree(config->krblevel);
  Fetch_safefree(config->oauth_bearer);
  Fetch_safefree(config->sasl_authzid);
  Fetch_safefree(config->unix_socket_path);
  Fetch_safefree(config->writeout);
  Fetch_safefree(config->proto_default);

  fetch_slist_free_all(config->quote);
  fetch_slist_free_all(config->postquote);
  fetch_slist_free_all(config->prequote);

  fetch_slist_free_all(config->headers);
  fetch_slist_free_all(config->proxyheaders);

  fetch_mime_free(config->mimepost);
  config->mimepost = NULL;
  tool_mime_free(config->mimeroot);
  config->mimeroot = NULL;
  config->mimecurrent = NULL;

  fetch_slist_free_all(config->telnet_options);
  fetch_slist_free_all(config->resolve);
  fetch_slist_free_all(config->connect_to);

  Fetch_safefree(config->preproxy);
  Fetch_safefree(config->proxy_service_name);
  Fetch_safefree(config->service_name);
  Fetch_safefree(config->ftp_account);
  Fetch_safefree(config->ftp_alternative_to_user);
  Fetch_safefree(config->aws_sigv4);
  Fetch_safefree(config->proto_str);
  Fetch_safefree(config->proto_redir_str);
  Fetch_safefree(config->ech);
  Fetch_safefree(config->ech_config);
  Fetch_safefree(config->ech_public);
}

void config_free(struct OperationConfig *config)
{
  struct OperationConfig *last = config;

  /* Free each of the structures in reverse order */
  while (last)
  {
    struct OperationConfig *prev = last->prev;

    free_config_fields(last);
    free(last);

    last = prev;
  }
}
