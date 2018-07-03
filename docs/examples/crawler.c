/* Simple web crawler (License: MIT)
 * Jeroen Ooms <jeroen@berkeley.edu>
 *
 * Compile using:
 *   gcc crawler.c $(pkg-config --cflags --libs libxml-2.0 libcurl)
 */

/* Parameters */
int max_total = 10000;
int max_concurrent = 500;
int max_connections = 200;
int max_link_per_page = 10;
char * start_page = "https://news.ycombinator.com";

#include <libxml/HTMLparser.h>
#include <libxml/xpath.h>
#include <libxml/uri.h>
#include <curl/curl.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <signal.h>

int pending_interrupt = 0;
void sighandler(int dummy) {
  pending_interrupt = 1;
}

/* resizable buffer */
typedef struct {
  char *buf;
  size_t size;
} memory;

size_t grow_buffer(void *contents, size_t sz, size_t nmemb, void *ctx) {
  size_t realsize = sz * nmemb;
  memory *mem = (memory*) ctx;
  mem->buf = realloc(mem->buf, mem->size + realsize);
  memcpy(&(mem->buf[mem->size]), contents, realsize);
  mem->size += realsize;
  return realsize;
}

CURL * make_handle(char * url){
  CURL * handle = curl_easy_init();

  /* Important: use HTTP2 over HTTPS */
  curl_easy_setopt(handle, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_2TLS);
  curl_easy_setopt(handle, CURLOPT_URL, url);

  /* buffer body */
  memory * mem = malloc(sizeof(memory));
  mem->size = 0;
  mem->buf = malloc(1);
  curl_easy_setopt(handle, CURLOPT_WRITEFUNCTION, grow_buffer);
  curl_easy_setopt(handle, CURLOPT_WRITEDATA, mem);
  curl_easy_setopt(handle, CURLOPT_PRIVATE, mem);

  /* For completeness */
  curl_easy_setopt(handle, CURLOPT_ENCODING, "gzip, deflate");
  curl_easy_setopt(handle, CURLOPT_TIMEOUT, 5L);
  curl_easy_setopt(handle, CURLOPT_FOLLOWLOCATION, 1L);
  curl_easy_setopt(handle, CURLOPT_MAXREDIRS, 10L);
  curl_easy_setopt(handle, CURLOPT_CONNECTTIMEOUT, 2L);
  curl_easy_setopt(handle, CURLOPT_COOKIEFILE, "");
  curl_easy_setopt(handle, CURLOPT_FILETIME, 1L);
  curl_easy_setopt(handle, CURLOPT_USERAGENT, "mini crawler");
  curl_easy_setopt(handle, CURLOPT_HTTPAUTH, CURLAUTH_ANY);
  curl_easy_setopt(handle, CURLOPT_UNRESTRICTED_AUTH, 1L);
  curl_easy_setopt(handle, CURLOPT_PROXYAUTH, CURLAUTH_ANY);
  curl_easy_setopt(handle, CURLOPT_EXPECT_100_TIMEOUT_MS, 0L);
  return handle;
}

/* HREF finder implemented in libxml2 but could be any HTML parser */
size_t follow_links(CURLM *multi_handle, memory * mem, char * url){
  int opts = HTML_PARSE_NOBLANKS | HTML_PARSE_NOERROR | HTML_PARSE_NOWARNING | HTML_PARSE_NONET;
  htmlDocPtr doc = htmlReadMemory(mem->buf, mem->size, url, NULL, opts);
  if(!doc)
    return 0;
  xmlChar * xpath = (xmlChar*) "//a/@href";
  xmlXPathContextPtr context = xmlXPathNewContext(doc);
  xmlXPathObjectPtr result = xmlXPathEvalExpression(xpath, context);
  xmlXPathFreeContext(context);
  if(!result)
    return 0;
  xmlNodeSetPtr nodeset = result->nodesetval;
  if(xmlXPathNodeSetIsEmpty(nodeset)){
    xmlXPathFreeObject(result);
    return 0;
  }
  size_t count = 0;
  for (int i = 0; i < nodeset->nodeNr; i++) {
    double r = rand();
    int x = r * nodeset->nodeNr / RAND_MAX;
    xmlChar * href = xmlNodeListGetString(doc, nodeset->nodeTab[x]->xmlChildrenNode, 1);
    char * absolute = (char *) xmlBuildURI(href, (xmlChar *) url);
    if(!absolute || strlen(absolute) < 20)
      continue;
    if(!strncmp(absolute, "http://", 7) || !strncmp(absolute, "https://", 8)){
      //printf("Following link (%d/%d): %s\n", x, nodeset->nodeNr, absolute);
      curl_multi_add_handle(multi_handle, make_handle(absolute));
      if(count++ == max_link_per_page)
        break;
    }
    xmlFree(href);
    xmlFree(absolute);
  }
  xmlXPathFreeObject (result);
  return count;
}

int main(void){
  signal(SIGINT, sighandler);
  LIBXML_TEST_VERSION;
  curl_global_init(CURL_GLOBAL_DEFAULT);
  CURLM *multi_handle = curl_multi_init();
  curl_multi_setopt(multi_handle, CURLMOPT_MAX_TOTAL_CONNECTIONS, max_connections);
  //curl_multi_setopt(multi_handle, CURLMOPT_MAX_HOST_CONNECTIONS, 6);

  //enable http/2 if available
  #ifdef CURLPIPE_MULTIPLEX
    curl_multi_setopt(multi_handle, CURLMOPT_PIPELINING, CURLPIPE_MULTIPLEX);
  #endif

  //set a html start page
  curl_multi_add_handle(multi_handle, make_handle(start_page));

  /* we start some action by calling perform right away */
  int msgs_left;
  int pending = 0;
  int complete = 0;
  int still_running = 1;
  while(still_running && !pending_interrupt) {
    int numfds;
    curl_multi_wait(multi_handle, NULL, 0, 1000, &numfds);
    curl_multi_perform(multi_handle, &still_running);

    /* See how the transfers went */
    CURLMsg *m = NULL;
    while((m = curl_multi_info_read(multi_handle, &msgs_left))) {
      if(m->msg == CURLMSG_DONE) {
        CURL *handle = m->easy_handle;
        char *url;
        memory * mem;
        curl_easy_getinfo(handle, CURLINFO_PRIVATE, &mem);
        curl_easy_getinfo(handle, CURLINFO_EFFECTIVE_URL, &url);
        if(m->data.result == CURLE_OK){
          long res_status;
          curl_easy_getinfo(handle, CURLINFO_RESPONSE_CODE, &res_status);
          if(res_status == 200){
            char *ct;
            curl_easy_getinfo(handle, CURLINFO_CONTENT_TYPE, &ct);
            printf("[%d] HTTP 200 (%s): %s\n", complete, ct, url);
            if(ct && strlen(ct) > 10 && strstr(ct, "text/html") && mem->size > 100){
              if(pending < max_concurrent && (complete + pending) < max_total){
                pending += follow_links(multi_handle, mem, url);
                still_running = 1;
              }
            }
          } else {
            printf("[%d] HTTP %d: %s\n", complete, (int) res_status, url);
          }
        } else {
          printf("[%d] Connection failure: %s\n", complete, url);
        }
        curl_multi_remove_handle(multi_handle, handle);
        curl_easy_cleanup(handle);
        free(mem->buf);
        free(mem);
        complete++;
        pending--;
      }
    }
  }
  curl_multi_cleanup(multi_handle);
  curl_global_cleanup();
  return 0;
}
