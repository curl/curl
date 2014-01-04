/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2014, Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at http://curl.haxx.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 ***************************************************************************/
/* This is an example application source code sending SMTP mail using the
 * multi interface.
 */

#include <string.h>
#include <curl/curl.h>

/*
 * This is the list of basic details you need to tweak to get things right.
 */
#define SERVER   "smtp.example.com"
#define PORT     ":587" /* it is a colon+port string, but you can set it
                           to "" to use the default port */
#define FROM     "<sender@example.com>"
#define TO       "<recipient@example.com>"
#define CC       "<info@example.com>"

#define MULTI_PERFORM_HANG_TIMEOUT 60 * 1000

static const char *payload_text[] = {
  "Date: Mon, 29 Nov 2010 21:54:29 +1100\r\n",
  "To: " TO "\r\n",
  "From: " FROM "(Example User)\r\n",
  "Cc: " CC "(Another example User)\r\n",
  "Message-ID: <dcd7cb36-11db-487a-9f3a-e652a9458efd@rfcpedant.example.org>\r\n",
  "Subject: SMTP TLS example message\r\n",
  "\r\n", /* empty line to divide headers from body, see RFC5322 */
  "The body of the message starts here.\r\n",
  "\r\n",
  "It could be a lot of lines, could be MIME encoded, whatever.\r\n",
  "Check RFC5322.\r\n",
  NULL
};

struct upload_status {
  int lines_read;
};

static size_t payload_source(void *ptr, size_t size, size_t nmemb, void *userp)
{
  struct upload_status *upload_ctx = (struct upload_status *)userp;
  const char *data;

  if((size == 0) || (nmemb == 0) || ((size*nmemb) < 1)) {
    return 0;
  }

  data = payload_text[upload_ctx->lines_read];

  if(data) {
    size_t len = strlen(data);
    memcpy(ptr, data, len);
    upload_ctx->lines_read++;

    return len;
  }

  return 0;
}

static struct timeval tvnow(void)
{
  /*
  ** time() returns the value of time in seconds since the Epoch.
  */
  struct timeval now;
  now.tv_sec = (long)time(NULL);
  now.tv_usec = 0;
  return now;
}

static long tvdiff(struct timeval newer, struct timeval older)
{
  return (newer.tv_sec-older.tv_sec)*1000+
    (newer.tv_usec-older.tv_usec)/1000;
}

int main(void)
{
  CURL *curl;
  CURLM *mcurl;
  int still_running = 1;
  struct timeval mp_start;
  struct curl_slist *recipients = NULL;
  struct upload_status upload_ctx;

  upload_ctx.lines_read = 0;

  curl_global_init(CURL_GLOBAL_DEFAULT);

  curl = curl_easy_init();
  if(!curl)
    return 1;

  mcurl = curl_multi_init();
  if(!mcurl)
    return 2;

  /* Add two recipients, in this particular case they correspond to the
   * To: and Cc: addressees in the header, but they could be any kind of
   * recipient. */
  recipients = curl_slist_append(recipients, TO);
  recipients = curl_slist_append(recipients, CC);

  curl_easy_setopt(curl, CURLOPT_URL, "smtp://" SERVER PORT);
  curl_easy_setopt(curl, CURLOPT_USERNAME, "user");
  curl_easy_setopt(curl, CURLOPT_PASSWORD, "secret");
  curl_easy_setopt(curl, CURLOPT_READFUNCTION, payload_source);
  curl_easy_setopt(curl, CURLOPT_READDATA, &upload_ctx);
  curl_easy_setopt(curl, CURLOPT_UPLOAD, 1L);
  curl_easy_setopt(curl, CURLOPT_MAIL_FROM, FROM);
  curl_easy_setopt(curl, CURLOPT_MAIL_RCPT, recipients);
  curl_easy_setopt(curl, CURLOPT_USE_SSL, (long)CURLUSESSL_ALL);
  curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
  curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
  curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
  curl_easy_setopt(curl, CURLOPT_SSLVERSION, 0L);
  curl_easy_setopt(curl, CURLOPT_SSL_SESSIONID_CACHE, 0L);
  curl_multi_add_handle(mcurl, curl);

  mp_start = tvnow();

  /* we start some action by calling perform right away */
  curl_multi_perform(mcurl, &still_running);

  while(still_running) {
    struct timeval timeout;
    int rc; /* select() return code */

    fd_set fdread;
    fd_set fdwrite;
    fd_set fdexcep;
    int maxfd = -1;

    long curl_timeo = -1;

    FD_ZERO(&fdread);
    FD_ZERO(&fdwrite);
    FD_ZERO(&fdexcep);

    /* set a suitable timeout to play around with */
    timeout.tv_sec = 1;
    timeout.tv_usec = 0;

    curl_multi_timeout(mcurl, &curl_timeo);
    if(curl_timeo >= 0) {
      timeout.tv_sec = curl_timeo / 1000;
      if(timeout.tv_sec > 1)
        timeout.tv_sec = 1;
      else
        timeout.tv_usec = (curl_timeo % 1000) * 1000;
    }

    /* get file descriptors from the transfers */
    curl_multi_fdset(mcurl, &fdread, &fdwrite, &fdexcep, &maxfd);

    /* In a real-world program you OF COURSE check the return code of the
       function calls.  On success, the value of maxfd is guaranteed to be
       greater or equal than -1.  We call select(maxfd + 1, ...), specially in
       case of (maxfd == -1), we call select(0, ...), which is basically equal
       to sleep. */
    rc = select(maxfd+1, &fdread, &fdwrite, &fdexcep, &timeout);

    if (tvdiff(tvnow(), mp_start) > MULTI_PERFORM_HANG_TIMEOUT) {
      fprintf(stderr, "ABORTING TEST, since it seems "
              "that it would have run forever.\n");
      break;
    }

    switch(rc) {
    case -1:
      /* select error */
      break;
    case 0: /* timeout */
    default: /* action */
      curl_multi_perform(mcurl, &still_running);
      break;
    }
  }

  curl_slist_free_all(recipients);
  curl_multi_remove_handle(mcurl, curl);
  curl_multi_cleanup(mcurl);
  curl_easy_cleanup(curl);
  curl_global_cleanup();

  return 0;
}


