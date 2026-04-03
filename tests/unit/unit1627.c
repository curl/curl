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
#include "unitcheck.h"

#include "urldata.h"
#include "url.h"
#include "strcase.h"

static CURLcode test_unit1627(const char *arg)
{
  size_t i, j;
  /* existing schemes in different cases */
  static const char *okay[] = {
    /* all upper */
    "DICT", "FILE", "FTP", "FTPS", "GOPHER", "GOPHERS", "HTTP", "HTTPS",
    "IMAP", "IMAPS", "LDAP", "LDAPS", "MQTT", "MQTTS", "POP3", "POP3S",
    "RTSP", "SCP", "SFTP", "SMB", "SMBS", "SMTP", "SMTPS",
    "TELNET", "TFTP", "WS", "WSS",
    /* all lower */
    "dict", "file", "ftp", "ftps", "gopher", "gophers", "http", "https",
    "imap", "imaps", "ldap", "ldaps", "mqtt", "mqtts", "pop3", "pop3s",
    "rtsp", "scp", "sftp", "smb", "smbs", "smtp", "smtps",
    "telnet", "tftp", "ws", "wss",
    /* mixed */
    "diCt", "fIle", "Ftp", "ftpS", "Gopher", "gOphers", "htTp", "httPs",
    "imAP", "imaPS", "LDap", "LDAps", "mQTT", "mqtTS", "pOP3", "pOP3s",
    "RtsP", "ScP", "SFtP", "Smb", "smBS", "sMTP", "SMTPs",
    "TELNEt", "tFTP", "Ws", "wSS",
  };
  /* non-existing schemes */
  static const char *notokay[] = {
    "a", "A", "htt", "ttp", "httt", "http+", "HTTPP", "HTTPPS", "HTTSP",
    "GROPHER", "D1CT", "AbG", "zLQp", "mNrtW", "PkY", "bVcxZq", "LmO",
    "iUhyT", "rEwQA", "xSdfG", "nBvC", "pOiuY", "tRewQ", "aSdfG", "hJkl",
    "mNbV", "cXz", "pOiU", "yTrE", "wQaS", "dFghJ", "kLmN", "bVcX", "zPoI",
    "uYtR", "eWqA", "sDfG", "hJkL", "zXcV", "bNmM", "qWeR", "tYuI", "oPaS",
    "dFgH", "jKlZ", "xCvB", "nMqW", "eRtY", "uIoP", "aSdF", "gHjK", "lZxC",
    "vBnM", "QwEr", "TyUi", "OpAs", "DfGh", "JkLz", "XcVb", "NmqW", "ErTy",
    "UiOp", "AsDf", "GhJk", "LzXc", "VbNm", "qweR", "tyuI", "opaD", "fghJ",
    "klzx", "cvbn", "mQW", "ErTy", "UiOp", "AsDf", "GhJk", "LzXc", "VbNm",
    "QwEr", "TyUi", "OpAs", "DfGh", "JkLz", "XcVb", "NmqW", "ErTy", "UiOp",
    "AsDf", "GhJk", "LzXc", "VbNm", "qWeR", "tYuI", "oPaS", "dFgH", "jKlZ",
    "xCvB", "nMqW", "eRtY", "uIoP", "aSdF", "gHjK", "lZxC", "vBnM", "QwEr",
    "TyUi", "OpAs", "DfGh", "JkLz", "XcVb", "NmqW", "ErTy", "UiOp", "AsDf",
    "GhJk", "LzXc", "VbNm"
  };

  (void)arg;

  for(i = 0; i < CURL_ARRAYSIZE(okay); i++) {
    char buffer[32];
    const struct Curl_scheme *get = Curl_get_scheme(okay[i]);
    if(get) {
      /* verify that we got the correct scheme */
      if(!curl_strequal(get->name, okay[i]))
        get = NULL;
    }
    if(!get) {
      curl_mprintf("Input: %s, expected okay\n", okay[i]);
      break;
    }
    Curl_strntolower(buffer, okay[i], strlen(okay[i]));
    buffer[ strlen(okay[i]) ] = 0;
    if(strcmp(buffer, get->name)) {
      curl_mprintf("Input: %s is not lowercase: %s\n", buffer, get->name);
      break;
    }
  }
  for(j = 0; j < CURL_ARRAYSIZE(notokay); j++) {
    const struct Curl_scheme *get = Curl_get_scheme(notokay[j]);
    if(get) {
      curl_mprintf("Input: %s, expected not okay\n", notokay[j]);
      break;
    }
  }

  curl_mprintf("%zu invokes\n", i + j);

  if(i != CURL_ARRAYSIZE(okay))
    return CURLE_FAILED_INIT;
  if(j != CURL_ARRAYSIZE(notokay))
    return CURLE_FAILED_INIT;

  return CURLE_OK;
}
