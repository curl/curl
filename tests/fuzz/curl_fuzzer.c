/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 2017, Max Dymond, <cmeister2@gmail.com>, et al.
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

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <curl/curl.h>
#include "curl_fuzzer.h"

/**
 * Fuzzing entry point. This function is passed a buffer containing a test
 * case.  This test case should drive the CURL API into making a request.
 */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  int rc = 0;
  int tlv_rc;
  FUZZ_DATA fuzz;
  TLV tlv;

  if(size < sizeof(TLV_RAW)) {
    /* Not enough data */
    goto EXIT_LABEL;
  }

  /* Try to initialize the fuzz data */
  FTRY(fuzz_initialize_fuzz_data(&fuzz, data, size));

  for(tlv_rc = fuzz_get_first_tlv(&fuzz, &tlv);
      tlv_rc == 0;
      tlv_rc = fuzz_get_next_tlv(&fuzz, &tlv)) {
    /* Have the TLV in hand. Parse the TLV. */
    fuzz_parse_tlv(&fuzz, &tlv);
  }

  if(tlv_rc != TLV_RC_NO_MORE_TLVS) {
    /* A TLV call failed. Can't continue. */
    goto EXIT_LABEL;
  }

  /* Do the CURL stuff! */
  curl_easy_perform(fuzz.easy);

EXIT_LABEL:

  fuzz_terminate_fuzz_data(&fuzz);

  /* This function must always return 0. Non-zero codes are reserved. */
  return 0;
}

/**
 * Utility function to convert 4 bytes to a u32 predictably.
 */
uint32_t to_u32(uint8_t b[4])
{
  uint32_t u;
  u = (b[0] << 24) + (b[1] << 16) + (b[2] << 8) + b[3];
  return u;
}

/**
 * Utility function to convert 2 bytes to a u16 predictably.
 */
uint16_t to_u16(uint8_t b[2])
{
  uint16_t u;
  u = (b[0] << 8) + b[1];
  return u;
}

/**
 * Initialize the local fuzz data structure.
 */
int fuzz_initialize_fuzz_data(FUZZ_DATA *fuzz,
                              const uint8_t *data,
                              size_t data_len)
{
  int rc = 0;

  /* Initialize the fuzz data. */
  memset(fuzz, 0, sizeof(FUZZ_DATA));

  /* Create an easy handle. This will have all of the settings configured on
     it. */
  fuzz->easy = curl_easy_init();
  FCHECK(fuzz->easy != NULL);

  /* Set some standard options on the CURL easy handle. We need to override the
     socket function so that we create our own sockets to present to CURL. */
  FTRY(curl_easy_setopt(fuzz->easy,
                        CURLOPT_OPENSOCKETFUNCTION,
                        fuzz_open_socket));
  FTRY(curl_easy_setopt(fuzz->easy, CURLOPT_OPENSOCKETDATA, fuzz));

  /* In case something tries to set a socket option, intercept this. */
  FTRY(curl_easy_setopt(fuzz->easy,
                        CURLOPT_SOCKOPTFUNCTION,
                        fuzz_sockopt_callback));

  /* Can enable verbose mode */
  /* FTRY(curl_easy_setopt(fuzz->easy, CURLOPT_VERBOSE, 1L)); */

  /* Set up the state parser */
  fuzz->state.data = data;
  fuzz->state.data_len = data_len;

EXIT_LABEL:

  return rc;
}

/**
 * Terminate the fuzz data structure, including freeing any allocated memory.
 */
void fuzz_terminate_fuzz_data(FUZZ_DATA *fuzz)
{
  fuzz_free((void **)&fuzz->url);
  fuzz_free((void **)&fuzz->username);
  fuzz_free((void **)&fuzz->password);
  fuzz_free((void **)&fuzz->postfields);

  if(fuzz->easy != NULL) {
    curl_easy_cleanup(fuzz->easy);
    fuzz->easy = NULL;
  }
}

/**
 * If a pointer has been allocated, free that pointer.
 */
void fuzz_free(void **ptr)
{
  if(*ptr != NULL) {
    free(*ptr);
    *ptr = NULL;
  }
}

/**
 * Function for providing a socket to CURL already primed with data.
 */
static curl_socket_t fuzz_open_socket(void *ptr,
                                      curlsocktype purpose,
                                      struct curl_sockaddr *address)
{
  FUZZ_DATA *fuzz = (FUZZ_DATA *)ptr;
  int fds[2];
  curl_socket_t server_fd;
  curl_socket_t client_fd;

  /* Handle unused parameters */
  (void)purpose;
  (void)address;

  if(socketpair(AF_UNIX, SOCK_STREAM, 0, fds)) {
    /* Failed to create a pair of sockets. */
    return CURL_SOCKET_BAD;
  }

  server_fd = fds[0];
  client_fd = fds[1];

  /* Try and write the response data to the server file descriptor so the
     client can read it. */
  if(write(server_fd,
           fuzz->rsp1_data,
           fuzz->rsp1_data_len) != (ssize_t)fuzz->rsp1_data_len) {
    /* Failed to write the data. */
    return CURL_SOCKET_BAD;
  }

  if(shutdown(server_fd, SHUT_WR)) {
    return CURL_SOCKET_BAD;
  }

  return client_fd;
}

/**
 * Callback function for setting socket options on the sockets created by
 * fuzz_open_socket. In our testbed the sockets are "already connected".
 */
static int fuzz_sockopt_callback(void *ptr,
                                 curl_socket_t curlfd,
                                 curlsocktype purpose)
{
  (void)ptr;
  (void)curlfd;
  (void)purpose;

  return CURL_SOCKOPT_ALREADY_CONNECTED;
}

/**
 * TLV access function - gets the first TLV from a data stream.
 */
int fuzz_get_first_tlv(FUZZ_DATA *fuzz,
                       TLV *tlv)
{
  /* Reset the cursor. */
  fuzz->state.data_pos = 0;
  return fuzz_get_tlv_comn(fuzz, tlv);
}

/**
 * TLV access function - gets the next TLV from a data stream.
*/
int fuzz_get_next_tlv(FUZZ_DATA *fuzz,
                      TLV *tlv)
{
  /* Advance the cursor by the full length of the previous TLV. */
  fuzz->state.data_pos += sizeof(TLV_RAW) + tlv->length;

  /* Work out if there's a TLV's worth of data to read */
  if(fuzz->state.data_pos + sizeof(TLV_RAW) > fuzz->state.data_len) {
    /* No more TLVs to parse */
    return TLV_RC_NO_MORE_TLVS;
  }

  return fuzz_get_tlv_comn(fuzz, tlv);
}

/**
 * Common TLV function for accessing TLVs in a data stream.
 */
int fuzz_get_tlv_comn(FUZZ_DATA *fuzz,
                      TLV *tlv)
{
  int rc = 0;
  size_t data_offset;
  TLV_RAW *raw;

  /* Start by casting the data stream to a TLV. */
  raw = (TLV_RAW *)&fuzz->state.data[fuzz->state.data_pos];
  data_offset = fuzz->state.data_pos + sizeof(TLV_RAW);

  /* Set the TLV values. */
  tlv->type = to_u16(raw->raw_type);
  tlv->length = to_u32(raw->raw_length);
  tlv->value = &fuzz->state.data[data_offset];

  /* Sanity check that the TLV length is ok. */
  if(data_offset + tlv->length > fuzz->state.data_len) {
    rc = TLV_RC_SIZE_ERROR;
  }

  return rc;
}

/**
 * Do different actions on the CURL handle for different received TLVs.
 */
int fuzz_parse_tlv(FUZZ_DATA *fuzz, TLV *tlv)
{
  int rc;

  switch(tlv->type) {
    case TLV_TYPE_URL:
      FCHECK(fuzz->url == NULL);
      fuzz->url = fuzz_tlv_to_string(tlv);
      FTRY(curl_easy_setopt(fuzz->easy, CURLOPT_URL, fuzz->url));
      break;

    case TLV_TYPE_RESPONSE1:
      /* The pointers in the TLV will always be valid as long as the fuzz data
         is in scope, which is the entirety of this file. */
      fuzz->rsp1_data = tlv->value;
      fuzz->rsp1_data_len = tlv->length;
      break;

    case TLV_TYPE_USERNAME:
      FCHECK(fuzz->username == NULL);
      fuzz->username = fuzz_tlv_to_string(tlv);
      FTRY(curl_easy_setopt(fuzz->easy, CURLOPT_USERNAME, fuzz->username));
      break;

    case TLV_TYPE_PASSWORD:
      FCHECK(fuzz->password == NULL);
      fuzz->password = fuzz_tlv_to_string(tlv);
      FTRY(curl_easy_setopt(fuzz->easy, CURLOPT_PASSWORD, fuzz->password));
      break;

    case TLV_TYPE_POSTFIELDS:
      FCHECK(fuzz->postfields == NULL);
      fuzz->postfields = fuzz_tlv_to_string(tlv);
      FTRY(curl_easy_setopt(fuzz->easy, CURLOPT_POSTFIELDS, fuzz->postfields));
      break;

    default:
      /* The fuzzer generates lots of unknown TLVs, so don't do anything if
         the TLV isn't known. */
      break;
  }

  rc = 0;

EXIT_LABEL:

  return rc;
}

/**
 * Converts a TLV data and length into an allocated string.
 */
char *fuzz_tlv_to_string(TLV *tlv)
{
  char *tlvstr;

  /* Allocate enough space, plus a null terminator */
  tlvstr = malloc(tlv->length + 1);

  if(tlvstr != NULL) {
    memcpy(tlvstr, tlv->value, tlv->length);
    tlvstr[tlv->length] = 0;
  }

  return tlvstr;
}
