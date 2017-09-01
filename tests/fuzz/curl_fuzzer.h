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

#include <curl/curl.h>

/**
 * TLV types.
 */
#define TLV_TYPE_URL                    1
#define TLV_TYPE_RESPONSE1              2
#define TLV_TYPE_USERNAME               3
#define TLV_TYPE_PASSWORD               4
#define TLV_TYPE_POSTFIELDS             5

/**
 * TLV function return codes.
 */
#define TLV_RC_NO_ERROR                 0
#define TLV_RC_NO_MORE_TLVS             1
#define TLV_RC_SIZE_ERROR               2

/**
 * Byte stream representation of the TLV header. Casting the byte stream
 * to a TLV_RAW allows us to examine the type and length.
 */
typedef struct tlv_raw
{
  /* Type of the TLV - 16 bits. */
  uint8_t raw_type[2];

  /* Length of the TLV data - 32 bits. */
  uint8_t raw_length[4];

} TLV_RAW;

typedef struct tlv
{
  /* Type of the TLV */
  uint16_t type;

  /* Length of the TLV data */
  uint32_t length;

  /* Pointer to data if length > 0. */
  const uint8_t *value;

} TLV;

/**
 * Internal state when parsing a TLV data stream.
 */
typedef struct fuzz_parse_state
{
  /* Data stream */
  const uint8_t *data;
  size_t data_len;

  /* Current position of our "cursor" in processing the data stream. */
  size_t data_pos;

} FUZZ_PARSE_STATE;

/**
 * Data local to a fuzzing run.
 */
typedef struct fuzz_data
{
  /* CURL easy object */
  CURL *easy;

  /* Parser state */
  FUZZ_PARSE_STATE state;

  /* Current URL. */
  char *url;

  /* Response data and length */
  const uint8_t *rsp1_data;
  size_t rsp1_data_len;

  /* Username and password */
  char *username;
  char *password;

  /* Postfields */
  char *postfields;

} FUZZ_DATA;

/* Function prototypes */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);
uint32_t to_u32(uint8_t b[4]);
uint16_t to_u16(uint8_t b[2]);
int fuzz_initialize_fuzz_data(FUZZ_DATA *fuzz,
                              const uint8_t *data,
                              size_t data_len);
void fuzz_terminate_fuzz_data(FUZZ_DATA *fuzz);
void fuzz_free(void **ptr);
static curl_socket_t fuzz_open_socket(void *ptr,
                                      curlsocktype purpose,
                                      struct curl_sockaddr *address);
static int fuzz_sockopt_callback(void *ptr,
                                 curl_socket_t curlfd,
                                 curlsocktype purpose);
int fuzz_get_first_tlv(FUZZ_DATA *fuzz, TLV *tlv);
int fuzz_get_next_tlv(FUZZ_DATA *fuzz, TLV *tlv);
int fuzz_get_tlv_comn(FUZZ_DATA *fuzz, TLV *tlv);
int fuzz_parse_tlv(FUZZ_DATA *fuzz, TLV *tlv);
char *fuzz_tlv_to_string(TLV *tlv);

/* Macros */
#define FTRY(FUNC)                                                             \
        {                                                                      \
          int _func_rc = (FUNC);                                               \
          if (_func_rc)                                                        \
          {                                                                    \
            rc = _func_rc;                                                     \
            goto EXIT_LABEL;                                                   \
          }                                                                    \
        }

#define FCHECK(COND)                                                           \
        {                                                                      \
          if (!(COND))                                                         \
          {                                                                    \
            rc = 1;                                                            \
            goto EXIT_LABEL;                                                   \
          }                                                                    \
        }
