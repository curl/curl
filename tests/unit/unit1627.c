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

#define ITERATIONS1627 1 /* edit for performance measurements */

static CURLcode test_unit1627(const char *arg)
{
  UNITTEST_BEGIN_SIMPLE

  size_t i = 0, j = 0, a;
  /* existing schemes in different cases */
  static const char * const okay[] = {
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

    "SOCKS", "SOCKS4", "SOCKS5", "SOCKS4A", "SOCKS5H",
    "socks", "socks4", "socks5", "socks4a", "socks5h",
    "Socks", "sOcks4", "soCks5", "socKs4a", "sockS5h",
  };
  /* non-existing schemes */
  static const char * const notokay[] = {
    "a", "A", "ht", "tt", "tt", "p+", "TPP", "PPS", "TSP",
    "HER", "1CT", "AbG", "LQp", "rtW", "PkY", "xZq", "LmO",
    "hyT", "wQA", "dfG", "BvC", "iuY", "ewQ", "dfG", "Jkl",
    "NbV", "cXz", "OiU", "SrE", "QaS", "ghJ", "LmN", "VcX", "PoI",
    "YtR", "WqA", "DfG", "JkL", "XcV", "NmM", "WeR", "YuI", "PaS",

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
    "GhJk", "LzXc", "VbNm",

    "aa", "Aa", "htta", "ttpa", "httta", "http+a", "HTTPPa", "HTTPPSa",
    "HTTSPa", "GROPHERa", "D1CTa", "AbGa", "zLQpa", "mNrtWa", "PkYa",
    "bVcxZqa", "LmOa", "iUhyTa", "rEwQAa", "xSdfGa", "nBvCa", "pOiuYa",
    "tRewQa", "aSdfGa", "hJkla", "mNbVa", "cXza", "pOiUa", "yTrEa", "wQaSa",
    "dFghJa", "kLmNa", "bVcXa", "zPoIa", "uYtRa", "eWqAa", "sDfGa", "hJkLa",
    "zXcVa", "bNmMa", "qWeRa", "tYuIa", "oPaSa", "dFgHa", "jKlZa", "xCvBa",
    "nMqWa", "eRtYa", "uIoPa", "aSdFa", "gHjKa", "lZxCa", "vBnMa", "QwEra",
    "TyUia", "OpAsa", "DfGha", "JkLza", "XcVba", "NmqWa", "ErTya", "UiOpa",
    "AsDfa", "GhJka", "LzXca", "VbNma", "qweRa", "tyuIa", "opaDa", "fghJa",
    "klzxa", "cvbna", "mQWa", "ErTya", "UiOpa", "AsDfa", "GhJka", "LzXca",
    "VbNma", "QwEra", "TyUia", "OpAsa", "DfGha", "JkLza", "XcVba", "NmqWa",
    "ErTya", "UiOpa", "AsDfa", "GhJka", "LzXca", "VbNma", "qWeRa", "tYuIa",
    "oPaSa", "dFgHa", "jKlZa", "xCvBa", "nMqWa", "eRtYa", "uIoPa", "aSdFa",
    "gHjKa", "lZxCa", "vBnMa", "QwEra", "TyUia", "OpAsa", "DfGha", "JkLza",
    "XcVba", "NmqWa", "ErTya", "UiOpa", "AsDfa", "GhJka", "LzXca", "VbNma",

    "aab", "Aab", "httab", "ttpab", "htttab", "http+ab", "HTTPPab", "HTTPPSab",
    "HTTSPab", "GROPHERab", "D1CTab", "AbGab", "zLQpab", "mNrtWab", "PkYab",
    "bVcxZqab", "LmOab", "iUhyTab", "rEwQAab", "xSdfGab", "nBvCab", "pOiuYab",
    "tRewQab", "aSdfGab", "hJklab", "mNbVab", "cXzab", "pOiUab", "yTrEab",
    "wQaSab", "dFghJab", "kLmNab", "bVcXab", "zPoIab", "uYtRab", "eWqAab",
    "sDfGab", "hJkLab", "zXcVab", "bNmMab", "qWeRab", "tYuIab", "oPaSab",
    "dFgHab", "jKlZab", "xCvBab", "nMqWab", "eRtYab", "uIoPab", "aSdFab",
    "gHjKab", "lZxCab", "vBnMab", "QwErab", "TyUiab", "OpAsab", "DfGhab",
    "JkLzab", "XcVbab", "NmqWab", "ErTyab", "UiOpab", "AsDfab", "GhJkab",
    "LzXcab", "VbNmab", "qweRab", "tyuIab", "opaDab", "fghJab", "klzxab",
    "cvbnab", "mQWab", "ErTyab", "UiOpab", "AsDfab", "GhJkab", "LzXcab",
    "VbNmab", "QwErab", "TyUiab", "OpAsab", "DfGhab", "JkLzab", "XcVbab",
    "NmqWab", "ErTyab", "UiOpab", "AsDfab", "GhJkab", "LzXcab", "VbNmab",
    "qWeRab", "tYuIab", "oPaSab", "dFgHab", "jKlZab", "xCvBab", "nMqWab",
    "eRtYab", "uIoPab", "aSdFab", "gHjKab", "lZxCab", "vBnMab", "QwErab",
    "TyUiab", "OpAsab", "DfGhab", "JkLzab", "XcVbab", "NmqWab", "ErTyab",
    "UiOpab", "AsDfab", "GhJkab", "LzXcab", "VbNmab",

    "dictt", "filee", "ftpp", "ftpss", "gopherr", "gopherss", "httpp",
    "httpss", "imapp", "imapss", "ldapp", "ldapss", "mqttt", "mqttss",
    "pop33", "pop3ss", "rtspp", "scpp", "sftpp", "smbb", "smbss", "smtpp",
    "smtpss", "telnett", "tftpp", "wsw", "wsss",

    "DIC", "FIL", "FT", "TPS", "GOPHE", "OPHER", "HTT", "TTPS",
    "IMA", "APS", "LDA", "APS", "MQT", "TTS", "POP", "P3S",
    "RTS", "SC", "SFT", "SM", "BS", "SMT", "TPS",
    "TELNE", "TFT", "W", "S",
  };

  for(a = 0 ; a < ITERATIONS1627; a++) {

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
      buffer[strlen(okay[i])] = 0;
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
  }

  curl_mprintf("%zu invokes\n", (i + j) * ITERATIONS1627);

  if(i != CURL_ARRAYSIZE(okay) ||
     j != CURL_ARRAYSIZE(notokay))
    return CURLE_FAILED_INIT;

  UNITTEST_END_SIMPLE
}
