/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2016, Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at https://curl.haxx.se/docs/copyright.html.
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

#include "tool_cfgable.h"
#include "tool_main.h"

#include "memdebug.h" /* keep this as LAST include */

void config_init(struct OperationConfig* config)
{
  memset(config, 0, sizeof(struct OperationConfig));

  config->postfieldsize = -1;
  config->use_httpget = FALSE;
  config->create_dirs = FALSE;
  config->maxredirs = DEFAULT_MAXREDIRS;
  config->proto = CURLPROTO_ALL; /* FIXME: better to read from library */
  config->proto_present = FALSE;
  config->proto_redir = CURLPROTO_ALL & /* All except FILE, SCP and SMB */
                        ~(CURLPROTO_FILE | CURLPROTO_SCP | CURLPROTO_SMB |
                          CURLPROTO_SMBS);
  config->proto_redir_present = FALSE;
  config->proto_default = NULL;
  config->tcp_nodelay = TRUE; /* enabled by default */
}

static void free_config_fields(struct OperationConfig *config)
{
  struct getout *urlnode;

  Curl_safefree(config->random_file);
  Curl_safefree(config->egd_file);
  Curl_safefree(config->useragent);
  Curl_safefree(config->cookie);
  Curl_safefree(config->cookiejar);
  Curl_safefree(config->cookiefile);

  Curl_safefree(config->postfields);
  Curl_safefree(config->referer);

  Curl_safefree(config->headerfile);
  Curl_safefree(config->ftpport);
  Curl_safefree(config->iface);

  Curl_safefree(config->range);

  Curl_safefree(config->userpwd);
  Curl_safefree(config->tls_username);
  Curl_safefree(config->tls_password);
  Curl_safefree(config->tls_authtype);
  Curl_safefree(config->proxyuserpwd);
  Curl_safefree(config->proxy);

  Curl_safefree(config->dns_ipv6_addr);
  Curl_safefree(config->dns_ipv4_addr);
  Curl_safefree(config->dns_interface);
  Curl_safefree(config->dns_servers);

  Curl_safefree(config->noproxy);

  Curl_safefree(config->mail_from);
  curl_slist_free_all(config->mail_rcpt);
  Curl_safefree(config->mail_auth);

  Curl_safefree(config->netrc_file);

  urlnode = config->url_list;
  while(urlnode) {
    struct getout *next = urlnode->next;
    Curl_safefree(urlnode->url);
    Curl_safefree(urlnode->outfile);
    Curl_safefree(urlnode->infile);
    Curl_safefree(urlnode);
    urlnode = next;
  }
  config->url_list = NULL;
  config->url_last = NULL;
  config->url_get = NULL;
  config->url_out = NULL;

  Curl_safefree(config->cipher_list);
  Curl_safefree(config->cert);
  Curl_safefree(config->cert_type);
  Curl_safefree(config->cacert);
  Curl_safefree(config->capath);
  Curl_safefree(config->crlfile);
  Curl_safefree(config->pinnedpubkey);
  Curl_safefree(config->key);
  Curl_safefree(config->key_type);
  Curl_safefree(config->key_passwd);
  Curl_safefree(config->pubkey);
  Curl_safefree(config->hostpubmd5);
  Curl_safefree(config->engine);

  Curl_safefree(config->customrequest);
  Curl_safefree(config->krblevel);

  Curl_safefree(config->oauth_bearer);

  Curl_safefree(config->unix_socket_path);
  Curl_safefree(config->writeout);
  Curl_safefree(config->proto_default);

  curl_slist_free_all(config->quote);
  curl_slist_free_all(config->postquote);
  curl_slist_free_all(config->prequote);

  curl_slist_free_all(config->headers);
  curl_slist_free_all(config->proxyheaders);

  if(config->httppost) {
    curl_formfree(config->httppost);
    config->httppost = NULL;
  }
  config->last_post = NULL;

  curl_slist_free_all(config->telnet_options);
  curl_slist_free_all(config->resolve);
  curl_slist_free_all(config->connect_to);

  Curl_safefree(config->socksproxy);
  Curl_safefree(config->proxy_service_name);
  Curl_safefree(config->service_name);

  Curl_safefree(config->ftp_account);
  Curl_safefree(config->ftp_alternative_to_user);
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
