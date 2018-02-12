/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2017, Daniel Stenberg, <daniel@haxx.se>, et al.
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
/* <DESC>
 * Stream-parse a document using the streaming Expat parser.
 * </DESC>
 */
/* Written by David Strauss
 *
 * Expat => http://www.libexpat.org/
 *
 * gcc -Wall -I/usr/local/include xmlstream.c -lcurl -lexpat -o xmlstream
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include <expat.h>
#include <curl/curl.h>

struct MemoryStruct {
  char *memory;
  size_t size;
};

struct ParserStruct {
  int ok;
  size_t tags;
  size_t depth;
  struct MemoryStruct characters;
};

static void startElement(void *userData, const XML_Char *name,
                         const XML_Char **atts)
{
  struct ParserStruct *state = (struct ParserStruct *) userData;
  state->tags++;
  state->depth++;

  /* Get a clean slate for reading in character data. */
  free(state->characters.memory);
  state->characters.memory = NULL;
  state->characters.size = 0;
}

static void characterDataHandler(void *userData, const XML_Char *s, int len)
{
  struct ParserStruct *state = (struct ParserStruct *) userData;
  struct MemoryStruct *mem = &state->characters;

  mem->memory = realloc(mem->memory, mem->size + len + 1);
  if(mem->memory == NULL) {
    /* Out of memory. */
    fprintf(stderr, "Not enough memory (realloc returned NULL).\n");
    state->ok = 0;
    return;
  }

  memcpy(&(mem->memory[mem->size]), s, len);
  mem->size += len;
  mem->memory[mem->size] = 0;
}

static void endElement(void *userData, const XML_Char *name)
{
  struct ParserStruct *state = (struct ParserStruct *) userData;
  state->depth--;

  printf("%5lu   %10lu   %s\n", state->depth, state->characters.size, name);
}

static size_t parseStreamCallback(void *contents, size_t length, size_t nmemb,
                                  void *userp)
{
  XML_Parser parser = (XML_Parser) userp;
  size_t real_size = length * nmemb;
  struct ParserStruct *state = (struct ParserStruct *) XML_GetUserData(parser);

  /* Only parse if we're not already in a failure state. */
  if(state->ok && XML_Parse(parser, contents, real_size, 0) == 0) {
    int error_code = XML_GetErrorCode(parser);
    fprintf(stderr, "Parsing response buffer of length %lu failed"
            " with error code %d (%s).\n",
            real_size, error_code, XML_ErrorString(error_code));
    state->ok = 0;
  }

  return real_size;
}

int main(void)
{
  CURL *curl_handle;
  CURLcode res;
  XML_Parser parser;
  struct ParserStruct state;

  /* Initialize the state structure for parsing. */
  memset(&state, 0, sizeof(struct ParserStruct));
  state.ok = 1;

  /* Initialize a namespace-aware parser. */
  parser = XML_ParserCreateNS(NULL, '\0');
  XML_SetUserData(parser, &state);
  XML_SetElementHandler(parser, startElement, endElement);
  XML_SetCharacterDataHandler(parser, characterDataHandler);

  /* Initialize a libcurl handle. */
  curl_global_init(CURL_GLOBAL_DEFAULT);
  curl_handle = curl_easy_init();
  curl_easy_setopt(curl_handle, CURLOPT_URL,
                   "http://www.w3schools.com/xml/simple.xml");
  curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, parseStreamCallback);
  curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, (void *)parser);

  printf("Depth   Characters   Closing Tag\n");

  /* Perform the request and any follow-up parsing. */
  res = curl_easy_perform(curl_handle);
  if(res != CURLE_OK) {
    fprintf(stderr, "curl_easy_perform() failed: %s\n",
            curl_easy_strerror(res));
  }
  else if(state.ok) {
    /* Expat requires one final call to finalize parsing. */
    if(XML_Parse(parser, NULL, 0, 1) == 0) {
      int error_code = XML_GetErrorCode(parser);
      fprintf(stderr, "Finalizing parsing failed with error code %d (%s).\n",
              error_code, XML_ErrorString(error_code));
    }
    else {
      printf("                     --------------\n");
      printf("                     %lu tags total\n", state.tags);
    }
  }

  /* Clean up. */
  free(state.characters.memory);
  XML_ParserFree(parser);
  curl_easy_cleanup(curl_handle);
  curl_global_cleanup();

  return 0;
}
