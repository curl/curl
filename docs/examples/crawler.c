/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) Jeroen Ooms <jeroenooms@gmail.com>
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
/* <DESC>
 * Web crawler based on curl and libxml2 to stress-test curl with
 * hundreds of concurrent connections to various servers.
 * </DESC>
 */
/*
 * To compile:
 *   gcc crawler.c $(pkg-config --cflags --libs libxml-2.0 libcurl)
 */
#include <libxml/HTMLparser.h>
#include <libxml/xpath.h>
#include <libxml/uri.h>

#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <signal.h>

#include <curl/curl.h>

/* Parameters */
static int max_con = 200;
static int max_total = 20000;
static int max_requests = 500;
static size_t max_link_per_page = 5;
static int follow_relative_links = 0;
static const char *start_page = "https://www.reuters.com/";

static int pending_interrupt = 0;
static void sighandler(int dummy)
{
  (void)dummy;
  pending_interrupt = 1;
}

/* resizable buffer */
struct memory {
  char *buf;
  size_t size;
};

static size_t write_cb(void *contents, size_t sz, size_t nmemb, void *ctx)
{
  size_t realsize = sz * nmemb;
  struct memory *mem = (struct memory *)ctx;
  char *ptr = realloc(mem->buf, mem->size + realsize);
  if(!ptr) {
    /* out of memory */
    printf("not enough memory (realloc returned NULL)\n");
    return 0;
  }
  mem->buf = ptr;
  memcpy(&(mem->buf[mem->size]), contents, realsize);
  mem->size += realsize;
  return realsize;
}

static CURL *make_handle(const char *url)
{
  CURL *curl = curl_easy_init();
  struct memory *mem;

  /* Important: use HTTP2 over HTTPS */
  curl_easy_setopt(curl, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_2TLS);
  curl_easy_setopt(curl, CURLOPT_URL, url);

  /* buffer body */
  mem = malloc(sizeof(*mem));
  mem->size = 0;
  mem->buf = malloc(1);
  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_cb);
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, mem);
  curl_easy_setopt(curl, CURLOPT_PRIVATE, mem);

  /* For completeness */
  curl_easy_setopt(curl, CURLOPT_ACCEPT_ENCODING, "");
  curl_easy_setopt(curl, CURLOPT_TIMEOUT, 5L);
  curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
  /* only allow redirects to HTTP and HTTPS URLs */
  curl_easy_setopt(curl, CURLOPT_REDIR_PROTOCOLS_STR, "http,https");
  curl_easy_setopt(curl, CURLOPT_AUTOREFERER, 1L);
  curl_easy_setopt(curl, CURLOPT_MAXREDIRS, 10L);
  /* each transfer needs to be done within 20 seconds! */
  curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, 20000L);
  /* connect fast or fail */
  curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT_MS, 2000L);
  /* skip files larger than a gigabyte */
  curl_easy_setopt(curl, CURLOPT_MAXFILESIZE_LARGE,
                   (curl_off_t)1024 * 1024 * 1024);
  curl_easy_setopt(curl, CURLOPT_COOKIEFILE, "");
  curl_easy_setopt(curl, CURLOPT_FILETIME, 1L);
  curl_easy_setopt(curl, CURLOPT_USERAGENT, "mini crawler");
  curl_easy_setopt(curl, CURLOPT_HTTPAUTH, CURLAUTH_ANY);
  curl_easy_setopt(curl, CURLOPT_UNRESTRICTED_AUTH, 1L);
  curl_easy_setopt(curl, CURLOPT_PROXYAUTH, CURLAUTH_ANY);
  curl_easy_setopt(curl, CURLOPT_EXPECT_100_TIMEOUT_MS, 0L);
  return curl;
}

/* HREF finder implemented in libxml2 but could be any HTML parser */
static size_t follow_links(CURLM *multi, struct memory *mem, const char *url)
{
  int opts = HTML_PARSE_NOBLANKS | HTML_PARSE_NOERROR | HTML_PARSE_NOWARNING |
             HTML_PARSE_NONET;
  htmlDocPtr doc = htmlReadMemory(mem->buf, (int)mem->size, url, NULL, opts);
  size_t count;
  int i;
  xmlChar *xpath;
  xmlNodeSetPtr nodeset;
  xmlXPathContextPtr context;
  xmlXPathObjectPtr object;
  if(!doc)
    return 0;
  xpath = (xmlChar *)"//a/@href";
  context = xmlXPathNewContext(doc);
  object = xmlXPathEvalExpression(xpath, context);
  xmlXPathFreeContext(context);
  if(!object)
    return 0;
  nodeset = object->nodesetval;
  if(xmlXPathNodeSetIsEmpty(nodeset)) {
    xmlXPathFreeObject(object);
    return 0;
  }
  count = 0;
  for(i = 0; i < nodeset->nodeNr; i++) {
    double r = rand();
    int x = (int)(r * nodeset->nodeNr / RAND_MAX);
    const xmlNode *node = nodeset->nodeTab[x]->xmlChildrenNode;
    xmlChar *href = xmlNodeListGetString(doc, node, 1);
    char *link;
    if(follow_relative_links) {
      xmlChar *orig = href;
      href = xmlBuildURI(href, (xmlChar *)url);
      xmlFree(orig);
    }
    link = (char *)href;
    if(!link || strlen(link) < 20)
      continue;
    if(!strncmp(link, "http://", 7) || !strncmp(link, "https://", 8)) {
      curl_multi_add_handle(multi, make_handle(link));
      if(count++ == max_link_per_page)
        break;
    }
    xmlFree(link);
  }
  xmlXPathFreeObject(object);
  return count;
}

static int is_html(const char *ctype)
{
  return ctype != NULL && strlen(ctype) > 10 && strstr(ctype, "text/html");
}

int main(void)
{
  CURLM *multi;
  int msgs_left;
  int pending;
  int complete;
  int still_running;
  CURLcode result;

  result = curl_global_init(CURL_GLOBAL_ALL);
  if(result != CURLE_OK)
    return (int)result;

  signal(SIGINT, sighandler);
  LIBXML_TEST_VERSION
  multi = curl_multi_init();
  if(multi) {
    curl_multi_setopt(multi, CURLMOPT_MAX_TOTAL_CONNECTIONS, max_con);
    curl_multi_setopt(multi, CURLMOPT_MAX_HOST_CONNECTIONS, 6L);

    /* enables http/2 if available */
#ifdef CURLPIPE_MULTIPLEX
    curl_multi_setopt(multi, CURLMOPT_PIPELINING, CURLPIPE_MULTIPLEX);
#endif

    /* sets html start page */
    curl_multi_add_handle(multi, make_handle(start_page));

    pending = 0;
    complete = 0;
    still_running = 1;
    while(still_running && !pending_interrupt) {
      int numfds;
      CURLMsg *m;

      curl_multi_wait(multi, NULL, 0, 1000, &numfds);
      curl_multi_perform(multi, &still_running);

      /* See how the transfers went */
      m = NULL;
      while((m = curl_multi_info_read(multi, &msgs_left))) {
        if(m->msg == CURLMSG_DONE) {
          CURL *curl = m->easy_handle;
          char *url;
          struct memory *mem;
          curl_easy_getinfo(curl, CURLINFO_PRIVATE, &mem);
          curl_easy_getinfo(curl, CURLINFO_EFFECTIVE_URL, &url);
          if(m->data.result == CURLE_OK) {
            long res_status;
            curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &res_status);
            if(res_status == 200) {
              char *ctype;
              curl_easy_getinfo(curl, CURLINFO_CONTENT_TYPE, &ctype);
              printf("[%d] HTTP 200 (%s): %s\n", complete, ctype, url);
              if(is_html(ctype) && mem->size > 100) {
                if(pending < max_requests &&
                   (complete + pending) < max_total) {
                  pending += follow_links(multi, mem, url);
                  still_running = 1;
                }
              }
            }
            else {
              printf("[%d] HTTP %d: %s\n", complete, (int)res_status, url);
            }
          }
          else {
            printf("[%d] Connection failure: %s\n", complete, url);
          }
          curl_multi_remove_handle(multi, curl);
          curl_easy_cleanup(curl);
          free(mem->buf);
          free(mem);
          complete++;
          pending--;
        }
      }
    }
    curl_multi_cleanup(multi);
  }
  curl_global_cleanup();
  return 0;
}
