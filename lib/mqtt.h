#ifndef HEADER_CURL_MQTT_H
#define HEADER_CURL_MQTT_H
/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 2019 - 2020, Björn Stenberg, <bjorn@haxx.se>
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

#ifdef CURL_ENABLE_MQTT
extern const struct Curl_handler Curl_handler_mqtt;
#endif

struct mqtt_conn {
  enum {
    MQTT_CONNACK,
    MQTT_SUBACK,
    MQTT_SUBWAIT,    /* wait for subscribe response */
    MQTT_SUB_REMAIN  /* wait for the remainder of the subscribe response */
  } state;
  unsigned int packetid;
};

/* protocol-specific transfer-related data */
struct MQTT {
  char *sendleftovers;
  size_t nsend; /* size of sendleftovers */

  /* when receving a PUBLISH */
  size_t npacket; /* byte counter */
  unsigned char firstbyte;
};

#endif /* HEADER_CURL_MQTT_H */
