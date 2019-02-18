/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 2019, Björn Stenberg, <bjorn@haxx.se>
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

#include "curl_setup.h"

#ifndef CURL_DISABLE_MQTT

#include "urldata.h"
#include <curl/curl.h>
#include "transfer.h"
#include "sendf.h"
#include "progress.h"
#include "mqtt.h"
#include "select.h"
#include "strdup.h"
#include "url.h"
#include "escape.h"
#include "warnless.h"
#include "curl_printf.h"
#include "curl_memory.h"
#include "multiif.h"
#include "rand.h"

/* The last #include file should be: */
#include "memdebug.h"

#define MQTT_MSG_CONNECT   0x10
#define MQTT_MSG_PUBLISH   0x30
#define MQTT_MSG_SUBSCRIBE 0x82

#define MQTT_CONNACK_LEN 4
#define MQTT_SUBACK_LEN 5
#define MQTT_CLIENTID_LEN 12 /* "curl0123abcd" */
#define MQTT_HEADER_LEN 5    /* max 5 bytes */

/*
 * Forward declarations.
 */

static CURLcode mqtt_do(struct connectdata *conn, bool *done);
static CURLcode mqtt_doing(struct connectdata *conn, bool *done);
static int mqtt_getsock(struct connectdata *conn,
                        curl_socket_t *sock, int numsocks);

/*
 * MQTT protocol handler.
 */

const struct Curl_handler Curl_handler_mqtt = {
  "MQTT",                             /* scheme */
  ZERO_NULL,                          /* setup_connection */
  mqtt_do,                            /* do_it */
  ZERO_NULL,                          /* done */
  ZERO_NULL,                          /* do_more */
  ZERO_NULL,                          /* connect_it */
  ZERO_NULL,                          /* connecting */
  mqtt_doing,                         /* doing */
  ZERO_NULL,                          /* proto_getsock */
  mqtt_getsock,                       /* doing_getsock */
  ZERO_NULL,                          /* domore_getsock */
  ZERO_NULL,                          /* perform_getsock */
  ZERO_NULL,                          /* disconnect */
  ZERO_NULL,                          /* readwrite */
  ZERO_NULL,                          /* connection_check */
  PORT_MQTT,                          /* defport */
  CURLPROTO_MQTT,                     /* protocol */
  PROTOPT_NONE                        /* flags */
};

static CURLcode mqtt_busy_write(struct connectdata *conn,
                                char *buf, size_t len)
{
  CURLcode result = CURLE_OK;
  curl_socket_t sockfd = conn->sock[FIRSTSOCKET];

  while(len > 0) {
    ssize_t n;
    result = Curl_write(conn, sockfd, buf, len, &n);
    if(result && result != CURLE_AGAIN)
      break;
    buf += n;
    len -= n;
  }
  return result;
}

/* Generic function called by the multi interface to figure out what socket(s)
   to wait for and for what actions during the DOING and PROTOCONNECT states*/
static int mqtt_getsock(struct connectdata *conn,
                        curl_socket_t *sock, /* points to numsocks
                                                number of sockets */
                        int numsocks)
{
  (void)conn;
  (void)numsocks;
  sock[0] = conn->sock[FIRSTSOCKET];
  return GETSOCK_READSOCK(FIRSTSOCKET);
}

static CURLcode mqtt_connect(struct connectdata *conn)
{
  CURLcode result = CURLE_OK;
  const size_t client_id_offset = 14;
  const size_t packetlen = client_id_offset + MQTT_CLIENTID_LEN;
  const size_t curl_len = strlen("curl");
  char packet[32] = {
    MQTT_MSG_CONNECT,  /* packet type */
    0x00,              /* remaining length */
    0x00, 0x04,        /* protocol length */
    'M','Q','T','T',   /* protocol name */
    0x04,              /* protocol level */
    0x02,              /* CONNECT flag: CleanSession */
    0x00, 0x3c,        /* keep-alive 0 = disabled */
    0x00, 0x00         /* payload1 length */
  };
  packet[1] = (packetlen - 2) & 0x7f;
  packet[client_id_offset - 1] = MQTT_CLIENTID_LEN;

  memcpy(packet + client_id_offset, "curl", curl_len);
  result = Curl_rand_hex(conn->data,
                         (unsigned char *)packet + client_id_offset + curl_len,
                         MQTT_CLIENTID_LEN - curl_len + 1);
  if(!result)
    result = mqtt_busy_write(conn, packet, packetlen);
  return result;
}

static CURLcode mqtt_disconnect(struct connectdata *conn)
{
  CURLcode result = CURLE_OK;
  result = mqtt_busy_write(conn, (char *)"\xe0\x00", 2);
  return result;
}

static CURLcode mqtt_verify_connack(struct connectdata *conn)
{
  CURLcode result;
  curl_socket_t sockfd = conn->sock[FIRSTSOCKET];
  unsigned char readbuf[MQTT_CONNACK_LEN];
  ssize_t nread;

  result = Curl_read(conn, sockfd, (char *)readbuf, MQTT_CONNACK_LEN, &nread);
  if(result)
    goto fail;

  /* fixme */
  if(nread < MQTT_CONNACK_LEN) {
    result = CURLE_WEIRD_SERVER_REPLY;
    goto fail;
  }

  /* verify CONNACK */
  if(readbuf[0] != 0x20 ||
     readbuf[1] != 0x02 ||
     readbuf[2] != 0x00 ||
     readbuf[3] != 0x00)
    result = CURLE_WEIRD_SERVER_REPLY;

fail:
  return result;
}

static CURLcode mqtt_get_topic(struct connectdata *conn,
                               char **topic, size_t *topiclen)
{
  CURLcode result = CURLE_OK;
  char *path = conn->data->state.up.path;

  if(strlen(path) > 1) {
    result = Curl_urldecode(conn->data, path + 1, 0, topic, topiclen, FALSE);
  }
  else {
    failf(conn->data, "Error: No topic specified.");
    result = CURLE_URL_MALFORMAT;
  }
  return result;
}


static CURLcode mqtt_subscribe(struct connectdata *conn)
{
  CURLcode result = CURLE_OK;
  char *topic = NULL;
  size_t topiclen;
  unsigned char *packet = NULL;
  size_t packetlen;

  result = mqtt_get_topic(conn, &topic, &topiclen);
  if(result)
    goto fail;

  conn->proto.mqtt.packetid++;

  packetlen = topiclen + 7;
  packet = malloc(packetlen);
  if(!packet) {
    result = CURLE_OUT_OF_MEMORY;
    goto fail;
  }

  packet[0] = MQTT_MSG_SUBSCRIBE;
  packet[1] = (packetlen - 2) & 0xff;
  packet[2] = (conn->proto.mqtt.packetid >> 8) & 0xff;
  packet[3] = conn->proto.mqtt.packetid & 0xff;
  packet[4] = (topiclen >> 8) & 0xff;
  packet[5] = topiclen & 0xff;
  memcpy(packet + 6, topic, topiclen);
  packet[packetlen - 1] = 0;

  result = mqtt_busy_write(conn, (char *)packet, packetlen);

fail:
  if(topic)
    Curl_safefree(topic);
  if(packet)
    Curl_safefree(packet);
  return result;
}

static CURLcode mqtt_verify_suback(struct connectdata *conn)
{
  CURLcode result;
  curl_socket_t sockfd = conn->sock[FIRSTSOCKET];
  unsigned char readbuf[MQTT_SUBACK_LEN];
  ssize_t nread;
  struct mqtt_conn *mqtt = &conn->proto.mqtt;

  result = Curl_read(conn, sockfd, (char *)readbuf, MQTT_SUBACK_LEN, &nread);
  if(result)
    goto fail;

  /* fixme */
  if(nread < MQTT_SUBACK_LEN) {
    result = CURLE_WEIRD_SERVER_REPLY;
    goto fail;
  }

  /* verify SUBACK */
  if(readbuf[0] != 0x90 ||
     readbuf[1] != 0x03 ||
     readbuf[2] != ((mqtt->packetid >> 8) & 0xff) ||
     readbuf[3] != (mqtt->packetid & 0xff) ||
     readbuf[4] != 0x00)
    result = CURLE_WEIRD_SERVER_REPLY;

fail:
  return result;
}

static int mqtt_encode_len(char *buf, size_t len)
{
  unsigned char encoded;
  int i;

  for(i = 0; len > 0; i++) {
    encoded = len % 128;
    len = len / 128;
    if(len > 0)
      encoded = encoded | 128;
    buf[i] = encoded;
  }

  return i;
}

static CURLcode mqtt_publish(struct connectdata *conn)
{
  CURLcode result;
  char *payload = conn->data->set.postfields;
  size_t payloadlen = (size_t)conn->data->set.postfieldsize;
  char *topic = NULL;
  size_t topiclen;
  unsigned char *pkt = NULL;
  size_t i = 0;

  pkt = malloc(payloadlen + 10);
  if(!pkt) {
    result = CURLE_OUT_OF_MEMORY;
    goto fail;
  }

  result = mqtt_get_topic(conn, &topic, &topiclen);
  if(result)
    goto fail;

  /* assemble packet */
  pkt[i++] = MQTT_MSG_PUBLISH;
  i += mqtt_encode_len((char *)pkt + i, 2 + topiclen + payloadlen);
  pkt[i++] = (topiclen >> 8) & 0xff;
  pkt[i++] = (topiclen & 0xff);
  memcpy(pkt + i, topic, topiclen);
  i += topiclen;
  memcpy(pkt + i, payload, payloadlen);
  i += payloadlen;
  result = mqtt_busy_write(conn, (char *)pkt, i);

fail:
  if(pkt)
    Curl_safefree(pkt);
  if(topic)
    Curl_safefree(topic);

  return result;
}

static size_t mqtt_decode_len(char *buf, size_t buflen, size_t *lenbytes)
{
  size_t len = 0;
  size_t mult = 1;
  size_t i;
  unsigned char encoded = 128;

  for(i = 0; (i < buflen) && (encoded & 128); i++) {
    encoded = buf[i];
    len += (encoded & 127) * mult;
    mult *= 128;
  }

  *lenbytes = i;

  return len;
}

static CURLcode mqtt_read_publish(struct connectdata *conn)
{
  CURLcode result;
  curl_socket_t sockfd = conn->sock[FIRSTSOCKET];
  ssize_t nread;
  char *pkt = NULL;
  size_t remlen, lenbytes;
  char *ptr;
  size_t topiclen;
  size_t payloadlen;
  size_t packetidlen = 0;

  /* allocate enough for a short message */
  pkt = malloc(130);
  if(!pkt) {
    result = CURLE_OUT_OF_MEMORY;
    goto fail;
  }

  result = Curl_read(conn, sockfd, pkt, MQTT_HEADER_LEN, &nread);
  if(result)
    goto fail;

  /* we are expecting a PUBLISH message */
  if((pkt[0] & 0xf0) != MQTT_MSG_PUBLISH) {
    result = CURLE_WEIRD_SERVER_REPLY;
    goto fail;
  }

  /* if QoS is set, message contains packet id */
  if(pkt[0] & 6)
    packetidlen = 2;

  remlen = mqtt_decode_len(pkt + 1, 4, &lenbytes);

  /* reallocate a bigger buffer if necessary */
  if(remlen > 125) {
    char *newpkt = Curl_saferealloc(pkt, remlen + lenbytes + 1);
    if(!newpkt) {
      result = CURLE_OUT_OF_MEMORY;
      goto fail;
    }
    else
      pkt = newpkt;
  }

  /* read rest of packet */
  result = Curl_read(conn, sockfd,
                     (char *)(pkt + MQTT_HEADER_LEN),
                     1 + lenbytes + remlen - MQTT_HEADER_LEN,
                     &nread);
  if(result)
    goto fail;

  ptr = pkt + 1 + lenbytes; /* skip header + lenbytes */
  topiclen = (ptr[0] << 8) + ptr[1];
  payloadlen = remlen - 2 - topiclen - packetidlen;
  /* sanity check lengths */
  if(2 + topiclen + payloadlen + packetidlen > remlen) {
    result = CURLE_WEIRD_SERVER_REPLY;
    goto fail;
  }
  ptr += 2; /* skip topic length bytes */
  ptr += topiclen + packetidlen; /* skip topic + packet id */
  result = Curl_client_write(conn, CLIENTWRITE_BODY, ptr, payloadlen);
  if(result)
    goto fail;
  /* add a newline for readability */
  result = Curl_client_write(conn, CLIENTWRITE_BODY, (char *)"\n", 1);

fail:
  if(pkt)
    Curl_safefree(pkt);
  return result;
}

static CURLcode mqtt_do(struct connectdata *conn, bool *done)
{
  CURLcode result = CURLE_OK;
  struct Curl_easy *data = conn->data;
  struct mqtt_conn *mqtt = &conn->proto.mqtt;

  *done = FALSE; /* unconditionally */

  result = mqtt_connect(conn);
  if(result) {
    failf(data, "Error %d sending MQTT CONN request", result);
    return result;
  }
  mqtt->state = MQTT_CONNACK;
  return CURLE_OK;
}

static CURLcode mqtt_doing(struct connectdata *conn, bool *done)
{
  CURLcode result = CURLE_OK;
  struct mqtt_conn *mqtt = &conn->proto.mqtt;

  *done = FALSE;

  switch(mqtt->state) {
  case MQTT_CONNACK:
    result = mqtt_verify_connack(conn);
    if(result)
      break;

    if(conn->data->set.httpreq == HTTPREQ_POST) {
      result = mqtt_publish(conn);
      if(!result) {
        result = mqtt_disconnect(conn);
        *done = TRUE;
      }
    }
    else {
      result = mqtt_subscribe(conn);
      if(!result)
        mqtt->state = MQTT_SUBACK;
    }
    break;

  case MQTT_SUBACK:
    result = mqtt_verify_suback(conn);
    if(result)
      break;

    mqtt->state = MQTT_SUBWAIT;
    break;

  case MQTT_SUBWAIT:
    result = mqtt_read_publish(conn);
    if(result)
      break;
    break;

  default:
    failf(conn->data, "State not handled yet");
    *done = TRUE;
    break;
  }

  if(result == CURLE_AGAIN)
    result = CURLE_OK;
  return result;
}

#endif /*CURL_DISABLE_MQTT*/
