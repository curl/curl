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
#include <testinput.h>

/**
 * TLV types.
 */
#define TLV_TYPE_URL                    1
#define TLV_TYPE_RESPONSE1              2
#define TLV_TYPE_USERNAME               3
#define TLV_TYPE_PASSWORD               4
#define TLV_TYPE_POSTFIELDS             5
#define TLV_TYPE_HEADER                 6
#define TLV_TYPE_COOKIE                 7
#define TLV_TYPE_UPLOAD1                8
#define TLV_TYPE_RANGE                  9
#define TLV_TYPE_CUSTOMREQUEST          10
#define TLV_TYPE_MAIL_RECIPIENT         11
#define TLV_TYPE_MAIL_FROM              12

/**
 * TLV function return codes.
 */
#define TLV_RC_NO_ERROR                 0
#define TLV_RC_NO_MORE_TLVS             1
#define TLV_RC_SIZE_ERROR               2

/* Temporary write array size */
#define TEMP_WRITE_ARRAY_SIZE           10

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

  /* Temporary writefunction state */
  char write_array[TEMP_WRITE_ARRAY_SIZE];

  /* Response data and length */
  const uint8_t *rsp1_data;
  size_t rsp1_data_len;

  /* Upload data and length; */
  const uint8_t *upload1_data;
  size_t upload1_data_len;

  /* Singleton string fields. */
  char *url;
  char *username;
  char *password;
  char *postfields;
  char *cookie;
  char *range;
  char *customrequest;
  char *mail_from;

  /* List of headers */
  struct curl_slist *header_list;

  /* List of mail recipients */
  struct curl_slist *mail_recipients_list;

} FUZZ_DATA;

/* Function prototypes */
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
static size_t fuzz_read_callback(char *buffer,
                                 size_t size,
                                 size_t nitems,
                                 void *ptr);
static size_t fuzz_write_callback(void *contents,
                                  size_t size,
                                  size_t nmemb,
                                  void *ptr);
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
            rc = 255;                                                          \
            goto EXIT_LABEL;                                                   \
          }                                                                    \
        }

#define FSINGLETONTLV(TLVNAME, FIELDNAME, OPTNAME)                             \
    case TLVNAME:                                                              \
      FCHECK(fuzz->FIELDNAME == NULL);                                         \
      fuzz->FIELDNAME = fuzz_tlv_to_string(tlv);                               \
      FTRY(curl_easy_setopt(fuzz->easy, OPTNAME, fuzz->FIELDNAME));            \
      break