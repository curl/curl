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
/* <DESC>
 * Get a web page, extract the title with libxml.
 * </DESC>

 Written by Lars Nilsson

 GNU C++ compile command line suggestion (edit paths accordingly):

 g++ -Wall -I/opt/fetch/include -I/opt/libxml/include/libxml2 htmltitle.cpp \
 -o htmltitle -L/opt/fetch/lib -L/opt/libxml/lib -lfetch -lxml2
*/
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <string>
#include <fetch/fetch.h>
#include <libxml/HTMLparser.h>

//
//  Case-insensitive string comparison
//

#ifdef _WIN32
#define COMPARE(a, b) (!_stricmp((a), (b)))
#else
#define COMPARE(a, b) (!strcasecmp((a), (b)))
#endif

//
//  libxml callback context structure
//

struct Context
{
  Context() : addTitle(false) {}

  bool addTitle;
  std::string title;
};

//
//  libfetch variables for error strings and returned data

static char errorBuffer[FETCH_ERROR_SIZE];
static std::string buffer;

//
//  libfetch write callback function
//

static size_t writer(char *data, size_t size, size_t nmemb,
                     std::string *writerData)
{
  if (writerData == NULL)
    return 0;

  writerData->append(data, size * nmemb);

  return size * nmemb;
}

//
//  libfetch connection initialization
//

static bool init(FETCH *&conn, const char *url)
{
  FETCHcode code;

  conn = fetch_easy_init();

  if (conn == NULL)
  {
    fprintf(stderr, "Failed to create FETCH connection\n");
    exit(EXIT_FAILURE);
  }

  code = fetch_easy_setopt(conn, FETCHOPT_ERRORBUFFER, errorBuffer);
  if (code != FETCHE_OK)
  {
    fprintf(stderr, "Failed to set error buffer [%d]\n", code);
    return false;
  }

  code = fetch_easy_setopt(conn, FETCHOPT_URL, url);
  if (code != FETCHE_OK)
  {
    fprintf(stderr, "Failed to set URL [%s]\n", errorBuffer);
    return false;
  }

  code = fetch_easy_setopt(conn, FETCHOPT_FOLLOWLOCATION, 1L);
  if (code != FETCHE_OK)
  {
    fprintf(stderr, "Failed to set redirect option [%s]\n", errorBuffer);
    return false;
  }

  code = fetch_easy_setopt(conn, FETCHOPT_WRITEFUNCTION, writer);
  if (code != FETCHE_OK)
  {
    fprintf(stderr, "Failed to set writer [%s]\n", errorBuffer);
    return false;
  }

  code = fetch_easy_setopt(conn, FETCHOPT_WRITEDATA, &buffer);
  if (code != FETCHE_OK)
  {
    fprintf(stderr, "Failed to set write data [%s]\n", errorBuffer);
    return false;
  }

  return true;
}

//
//  libxml start element callback function
//

static void StartElement(void *voidContext,
                         const xmlChar *name,
                         const xmlChar **attributes)
{
  Context *context = static_cast<Context *>(voidContext);

  if (COMPARE(reinterpret_cast<const char *>(name), "TITLE"))
  {
    context->title = "";
    context->addTitle = true;
  }
  (void)attributes;
}

//
//  libxml end element callback function
//

static void EndElement(void *voidContext,
                       const xmlChar *name)
{
  Context *context = static_cast<Context *>(voidContext);

  if (COMPARE(reinterpret_cast<const char *>(name), "TITLE"))
    context->addTitle = false;
}

//
//  Text handling helper function
//

static void handleCharacters(Context *context,
                             const xmlChar *chars,
                             int length)
{
  if (context->addTitle)
    context->title.append(reinterpret_cast<const char *>(chars),
                          (unsigned long)length);
}

//
//  libxml PCDATA callback function
//

static void Characters(void *voidContext,
                       const xmlChar *chars,
                       int length)
{
  Context *context = static_cast<Context *>(voidContext);

  handleCharacters(context, chars, length);
}

//
//  libxml CDATA callback function
//

static void cdata(void *voidContext,
                  const xmlChar *chars,
                  int length)
{
  Context *context = static_cast<Context *>(voidContext);

  handleCharacters(context, chars, length);
}

//
//  libxml SAX callback structure
//

static htmlSAXHandler saxHandler =
    {
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        StartElement,
        EndElement,
        NULL,
        Characters,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        cdata,
        NULL,
        0,
        0,
        0,
        0,
        NULL};

//
//  Parse given (assumed to be) HTML text and return the title
//

static void parseHtml(const std::string &html,
                      std::string &title)
{
  htmlParserCtxtPtr ctxt;
  Context context;

  ctxt = htmlCreatePushParserCtxt(&saxHandler, &context, "", 0, "",
                                  XML_CHAR_ENCODING_NONE);

  htmlParseChunk(ctxt, html.c_str(), (int)html.size(), 0);
  htmlParseChunk(ctxt, "", 0, 1);

  htmlFreeParserCtxt(ctxt);

  title = context.title;
}

int main(int argc, char *argv[])
{
  FETCH *conn = NULL;
  FETCHcode code;
  std::string title;

  // Ensure one argument is given

  if (argc != 2)
  {
    fprintf(stderr, "Usage: %s <url>\n", argv[0]);
    exit(EXIT_FAILURE);
  }

  fetch_global_init(FETCH_GLOBAL_DEFAULT);

  // Initialize FETCH connection

  if (!init(conn, argv[1]))
  {
    fprintf(stderr, "Connection initialization failed\n");
    exit(EXIT_FAILURE);
  }

  // Retrieve content for the URL

  code = fetch_easy_perform(conn);
  fetch_easy_cleanup(conn);

  if (code != FETCHE_OK)
  {
    fprintf(stderr, "Failed to get '%s' [%s]\n", argv[1], errorBuffer);
    exit(EXIT_FAILURE);
  }

  // Parse the (assumed) HTML code
  parseHtml(buffer, title);

  // Display the extracted title
  printf("Title: %s\n", title.c_str());

  return EXIT_SUCCESS;
}
