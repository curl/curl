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

#include <stddef.h>

#include "tool_cfgable.h"
#include "tool_formparse.h"
#include "tool_libinfo.h"
#include "tool_paramhlp.h"
#include "tool_main.h"
#include "tool_msgs.h"

static struct GlobalConfig globalconf;
struct GlobalConfig *global;

struct OperationConfig *config_alloc(void)
{
  struct OperationConfig *config =
    curlx_calloc(1, sizeof(struct OperationConfig));
  if(!config)
    return NULL;

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
  return config;
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
#endif
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
  curlx_safefree(config->ssl_signature_algorithms);
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
  curlx_safefree(config->httpsig);
  curlx_safefree(config->httpsig_headers);
  curlx_safefree(config->httpsig_key);
  curlx_safefree(config->httpsig_keyid);
  curlx_safefree(config->ech);
  curlx_safefree(config->ech_config);
  curlx_safefree(config->ech_public);
  curlx_safefree(config->knownhosts);
}

void config_free(struct OperationConfig *config)
{
  struct OperationConfig *last = config;

  /* Free each of the structures in reverse order */
  while(last) {
    struct OperationConfig *prev = last->prev;

    free_config_fields(last);
    curlx_free(last);

    last = prev;
  }
}

#ifdef CURL_DEBUG_GLOBAL_MEM

#ifdef CURL_MEMDEBUG
#error "curl_global_init_mem() testing does not work with memdebug debugging"
#endif

/*
 * This is the custom memory functions handed to curl when we run special test
 * round to verify them.
 *
 * The main point is to make sure that what is returned is different than what
 * the regular memory functions return so that mixup will trigger problems.
 *
 * This test setup currently only works when building with a *shared* libcurl
 * and not static, as in the latter case the tool and the library share some of
 * the functions in incompatible ways.
 */

/*
 * This code appends this extra chunk of memory in front of every allocation
 * done by libcurl with the only purpose to cause trouble when using the wrong
 * free function on memory.
 */
struct extramem {
  size_t extra;
  union {
    curl_off_t o;
    double d;
    void *p;
  } mem[1];
};

static void *custom_calloc(size_t wanted_nmemb, size_t wanted_size)
{
  struct extramem *m;
  size_t sz = wanted_size * wanted_nmemb;
  sz += sizeof(struct extramem);
  m = curlx_calloc(1, sz);
  if(m)
    return m->mem;
  return NULL;
}

static void *custom_malloc(size_t wanted_size)
{
  struct extramem *m;
  size_t sz = wanted_size + sizeof(struct extramem);
  m = curlx_malloc(sz);
  if(m)
    return m->mem;
  return NULL;
}

static char *custom_strdup(const char *ptr)
{
  struct extramem *m;
  size_t len = strlen(ptr);
  size_t sz = len + sizeof(struct extramem);
  m = curlx_malloc(sz);
  if(m) {
    char *p = (char *)m->mem;
    /* since strcpy is banned, we do memcpy */
    memcpy(p, ptr, len);
    p[len] = 0;
    return (char *)m->mem;
  }
  return NULL;
}

static void *custom_realloc(void *ptr, size_t size)
{
  struct extramem *m = NULL;
  size_t sz = size + sizeof(struct extramem);
  if(ptr)
    /* if given a pointer, figure out the original */
    ptr = (void *)((char *)ptr - offsetof(struct extramem, mem));
  m = curlx_realloc(ptr, sz);
  if(m)
    return m->mem;
  return NULL;
}

static void custom_free(void *ptr)
{
  struct extramem *m = NULL;
  if(ptr) {
    m = (void *)((char *)ptr - offsetof(struct extramem, mem));
    curlx_free(m);
  }
}

#endif

/*
 * This is the main global constructor for the app. Call this before
 * _any_ libcurl usage. If this fails, *NO* libcurl functions may be
 * used, or havoc may be the result.
 */
CURLcode globalconf_init(void)
{
  CURLcode result = CURLE_OK;
  global = &globalconf;

#ifdef __DJGPP__
  /* stop stat() wasting time */
  _djstat_flags |= _STAT_INODE | _STAT_EXEC_MAGIC | _STAT_DIRSIZE;
#endif

  /* Initialise the global config */
  global->showerror = FALSE;          /* show errors when silent */
  global->styled_output = TRUE;       /* enable detection */
  global->parallel_max = PARALLEL_DEFAULT;

  /* Allocate the initial operate config */
  global->first = global->last = config_alloc();
  if(global->first) {
    /* Perform the libcurl initialization */
#ifdef CURL_DEBUG_GLOBAL_MEM
    result = curl_global_init_mem(CURL_GLOBAL_ALL, custom_malloc, custom_free,
                                  custom_realloc, custom_strdup,
                                  custom_calloc);
#else
    result = curl_global_init(CURL_GLOBAL_DEFAULT);
#endif
    if(!result) {
      /* Get information about libcurl */
      result = get_libcurl_info();

      if(result) {
        errorf("error retrieving curl library information");
        curlx_free(global->first);
      }
    }
    else {
      errorf("error initializing curl library");
      curlx_free(global->first);
    }
  }
  else {
    errorf("error initializing curl");
    result = CURLE_FAILED_INIT;
  }

  return result;
}

static void free_globalconfig(void)
{
  curlx_safefree(global->trace_dump);

  if(global->trace_fopened && global->trace_stream)
    curlx_fclose(global->trace_stream);
  global->trace_stream = NULL;

  curlx_safefree(global->ssl_sessions);
  curlx_safefree(global->libcurl);
#ifdef _WIN32
  curlx_free(global->term.buf);
#endif
}

/*
 * This is the main global destructor for the app. Call this after _all_
 * libcurl usage is done.
 */
void globalconf_free(void)
{
  /* Cleanup the easy handle */
  /* Main cleanup */
  curl_global_cleanup();
  free_globalconfig();

  /* Free the OperationConfig structures */
  config_free(global->last);
  global->first = NULL;
  global->last = NULL;
}
