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
/* <DESC>
 * Download a document and use libtidy to parse the HTML.
 * </DESC>
 */
/*
 * LibTidy => https://www.html-tidy.org/
 */
#include <stdio.h>

#include <tidy/tidy.h>
#include <tidy/tidybuffio.h>

#include <curl/curl.h>

/* curl write callback, to fill tidy's input buffer...  */
static uint write_cb(char *in, uint size, uint nmemb, TidyBuffer *out)
{
  uint r;
  r = size * nmemb;
  tidyBufAppend(out, in, r);
  return r;
}

/* Traverse the document tree */
static void dumpNode(TidyDoc doc, TidyNode tnod, int indent)
{
  TidyNode child;
  for(child = tidyGetChild(tnod); child; child = tidyGetNext(child)) {
    ctmbstr name = tidyNodeGetName(child);
    if(name) {
      /* if it has a name, then it is an HTML tag ... */
      TidyAttr attr;
      printf("%*.*s%s ", indent, indent, "<", name);
      /* walk the attribute list */
      for(attr = tidyAttrFirst(child); attr; attr = tidyAttrNext(attr)) {
        printf("%s", tidyAttrName(attr));
        tidyAttrValue(attr) ? printf("=\"%s\" ",
                                     tidyAttrValue(attr)) : printf(" ");
      }
      printf(">\n");
    }
    else {
      /* if it does not have a name, then it is probably text, cdata, etc... */
      TidyBuffer buf;
      tidyBufInit(&buf);
      tidyNodeGetText(doc, child, &buf);
      printf("%*.*s\n", indent, indent, buf.bp ? (char *)buf.bp : "");
      tidyBufFree(&buf);
    }
    dumpNode(doc, child, indent + 4); /* recursive */
  }
}

int main(int argc, const char **argv)
{
  CURL *curl;
  char curl_errbuf[CURL_ERROR_SIZE];
  TidyDoc tdoc;
  TidyBuffer docbuf = { 0 };
  TidyBuffer tidy_errbuf = { 0 };
  CURLcode result;

  if(argc != 2) {
    printf("usage: %s <url>\n", argv[0]);
    return 1;
  }

  result = curl_global_init(CURL_GLOBAL_ALL);
  if(result)
    return (int)result;

  tdoc = tidyCreate();
  tidyOptSetBool(tdoc, TidyForceOutput, yes); /* try harder */
  tidyOptSetInt(tdoc, TidyWrapLen, 4096);
  tidySetErrorBuffer(tdoc, &tidy_errbuf);
  tidyBufInit(&docbuf);

  curl = curl_easy_init();
  if(curl) {
    curl_easy_setopt(curl, CURLOPT_URL, argv[1]);
    curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, curl_errbuf);
    curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 0L);
    curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_cb);

    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &docbuf);
    result = curl_easy_perform(curl);
    if(!result) {
      result = tidyParseBuffer(tdoc, &docbuf); /* parse the input */
      if(result >= 0) {
        result = tidyCleanAndRepair(tdoc); /* fix any problems */
        if(result >= 0) {
          result = tidyRunDiagnostics(tdoc); /* load tidy error buffer */
          if(result >= 0) {
            dumpNode(tdoc, tidyGetRoot(tdoc), 0); /* walk the tree */
            fprintf(stderr, "%s\n", tidy_errbuf.bp); /* show errors */
          }
        }
      }
    }
    else
      fprintf(stderr, "%s\n", curl_errbuf);

    /* clean-up */
    curl_easy_cleanup(curl);
  }

  tidyBufFree(&docbuf);
  tidyBufFree(&tidy_errbuf);
  tidyRelease(tdoc);

  curl_global_cleanup();

  return (int)result;
}
