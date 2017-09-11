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
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  int rc = 0;
  int tlv_rc;
  FUZZ_DATA fuzz;
  TLV tlv;

  /* Have to set all fields to zero before getting to the terminate function */
  memset(&fuzz, 0, sizeof(FUZZ_DATA));

  if(size < sizeof(TLV_RAW)) {
    /* Not enough data for a single TLV - don't continue */
    goto EXIT_LABEL;
  }

  /* Try to initialize the fuzz data */
  FTRY(fuzz_initialize_fuzz_data(&fuzz, data, size));

  for(tlv_rc = fuzz_get_first_tlv(&fuzz, &tlv);
      tlv_rc == 0;
      tlv_rc = fuzz_get_next_tlv(&fuzz, &tlv)) {

    /* Have the TLV in hand. Parse the TLV. */
    rc = fuzz_parse_tlv(&fuzz, &tlv);

    if(rc != 0) {
      /* Failed to parse the TLV. Can't continue. */
      goto EXIT_LABEL;
    }
  }

  if(tlv_rc != TLV_RC_NO_MORE_TLVS) {
    /* A TLV call failed. Can't continue. */
    goto EXIT_LABEL;
  }

  /* Do the CURL stuff! */
  if(fuzz.header_list != NULL) {
    curl_easy_setopt(fuzz.easy, CURLOPT_HTTPHEADER, fuzz.header_list);
  }

  if(fuzz.mail_recipients_list != NULL) {
    curl_easy_setopt(fuzz.easy, CURLOPT_MAIL_RCPT, fuzz.mail_recipients_list);
  }

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

  /* Set the standard read function callback. */
  FTRY(curl_easy_setopt(fuzz->easy,
                        CURLOPT_READFUNCTION,
                        fuzz_read_callback));
  FTRY(curl_easy_setopt(fuzz->easy, CURLOPT_READDATA, fuzz));

  /* Set the standard write function callback. */
  FTRY(curl_easy_setopt(fuzz->easy,
                        CURLOPT_WRITEFUNCTION,
                        fuzz_write_callback));
  FTRY(curl_easy_setopt(fuzz->easy, CURLOPT_WRITEDATA, fuzz));

  /* Can enable verbose mode by changing 0L to 1L */
  FTRY(curl_easy_setopt(fuzz->easy, CURLOPT_VERBOSE, 0L));

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
  fuzz_free((void **)&fuzz->cookie);
  fuzz_free((void **)&fuzz->range);
  fuzz_free((void **)&fuzz->customrequest);
  fuzz_free((void **)&fuzz->mail_from);

  if(fuzz->header_list != NULL) {
    curl_slist_free_all(fuzz->header_list);
    fuzz->header_list = NULL;
  }

  if(fuzz->mail_recipients_list != NULL) {
    curl_slist_free_all(fuzz->mail_recipients_list);
    fuzz->mail_recipients_list = NULL;
  }

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
 * Callback function for doing data uploads.
 */
static size_t fuzz_read_callback(char *buffer,
                                 size_t size,
                                 size_t nitems,
                                 void *ptr)
{
  FUZZ_DATA *fuzz = (FUZZ_DATA *)ptr;
  curl_off_t nread;

  /* If no upload data has been specified, then return an error code. */
  if(fuzz->upload1_data_len == 0) {
    /* No data to upload */
    return CURL_READFUNC_ABORT;
  }

  /* Send the upload data. */
  memcpy(buffer,
         fuzz->upload1_data,
         fuzz->upload1_data_len);

  return fuzz->upload1_data_len;
}

/**
 * Callback function for handling data output quietly.
 */
static size_t fuzz_write_callback(void *contents,
                                  size_t size,
                                  size_t nmemb,
                                  void *ptr)
{
  size_t total = size * nmemb;
  FUZZ_DATA *fuzz = (FUZZ_DATA *)ptr;
  size_t copy_len = total;

  /* Restrict copy_len to at most TEMP_WRITE_ARRAY_SIZE. */
  if(copy_len > TEMP_WRITE_ARRAY_SIZE) {
    copy_len = TEMP_WRITE_ARRAY_SIZE;
  }

  /* Copy bytes to the temp store just to ensure the parameters are
     exercised. */
  memcpy(fuzz->write_array, contents, copy_len);

  return total;
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
  char *tmp;

  switch(tlv->type) {
    case TLV_TYPE_RESPONSE1:
      /* The pointers in the TLV will always be valid as long as the fuzz data
         is in scope, which is the entirety of this file. */
      fuzz->rsp1_data = tlv->value;
      fuzz->rsp1_data_len = tlv->length;
      break;

    case TLV_TYPE_UPLOAD1:
      /* The pointers in the TLV will always be valid as long as the fuzz data
         is in scope, which is the entirety of this file. */
      fuzz->upload1_data = tlv->value;
      fuzz->upload1_data_len = tlv->length;

      curl_easy_setopt(fuzz->easy, CURLOPT_UPLOAD, 1L);
      curl_easy_setopt(fuzz->easy,
                       CURLOPT_INFILESIZE_LARGE,
                       (curl_off_t)fuzz->upload1_data_len);
      break;

    case TLV_TYPE_HEADER:
      tmp = fuzz_tlv_to_string(tlv);
      fuzz->header_list = curl_slist_append(fuzz->header_list, tmp);
      fuzz_free((void **)&tmp);
      break;

    case TLV_TYPE_MAIL_RECIPIENT:
      tmp = fuzz_tlv_to_string(tlv);
      fuzz->mail_recipients_list =
                             curl_slist_append(fuzz->mail_recipients_list, tmp);
      fuzz_free((void **)&tmp);
      break;

    /* Define a set of singleton TLVs - they can only have their value set once
       and all follow the same pattern. */
    FSINGLETONTLV(TLV_TYPE_URL, url, CURLOPT_URL);
    FSINGLETONTLV(TLV_TYPE_USERNAME, username, CURLOPT_USERNAME);
    FSINGLETONTLV(TLV_TYPE_PASSWORD, password, CURLOPT_PASSWORD);
    FSINGLETONTLV(TLV_TYPE_POSTFIELDS, postfields, CURLOPT_POSTFIELDS);
    FSINGLETONTLV(TLV_TYPE_COOKIE, cookie, CURLOPT_COOKIE);
    FSINGLETONTLV(TLV_TYPE_RANGE, range, CURLOPT_RANGE);
    FSINGLETONTLV(TLV_TYPE_CUSTOMREQUEST, customrequest, CURLOPT_CUSTOMREQUEST);
    FSINGLETONTLV(TLV_TYPE_MAIL_FROM, mail_from, CURLOPT_MAIL_FROM);

    default:
      /* The fuzzer generates lots of unknown TLVs - we don't want these in the
         corpus so we reject any unknown TLVs. */
      rc = 255;
      goto EXIT_LABEL;
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
  tlvstr = (char *)malloc(tlv->length + 1);

  if(tlvstr != NULL) {
    memcpy(tlvstr, tlv->value, tlv->length);
    tlvstr[tlv->length] = 0;
  }

  return tlvstr;
}
