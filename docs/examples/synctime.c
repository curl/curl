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
/* <DESC>
 * Set your system time from a remote HTTP server's Date: header.
 * </DESC>
 */
/* This example code only builds as-is on Windows.
 *
 * Synchronising your computer clock via Internet time server usually relies
 * on DAYTIME, TIME, or NTP protocols. These protocols provide good accurate
 * time synchronization but it does not work well through a firewall/proxy.
 * Some adjustment has to be made to the firewall/proxy for these protocols to
 * work properly.
 *
 * There is an indirect method. Since most webserver provide server time in
 * their HTTP header, therefore you could synchronise your computer clock
 * using HTTP protocol which has no problem with firewall/proxy.
 *
 * For this software to work, you should take note of these items.
 * 1. Your firewall/proxy must allow your computer to surf Internet.
 * 2. Webserver system time must in sync with the NTP time server,
 *    or at least provide an accurate time keeping.
 * 3. Webserver HTTP header does not provide the milliseconds units,
 *    so there is no way to get an accurate time.
 * 4. This software could only provide an accuracy of +- a few seconds,
 *    as Round-Trip delay time is not taken into consideration.
 *    Compensation of network, firewall/proxy delay cannot be simply divide
 *    the Round-Trip delay time by half.
 * 5. Win32 SetSystemTime() API sets your computer clock according to
 *    GMT/UTC time. Therefore your computer timezone must be properly set.
 * 6. Webserver data should not be cached by the proxy server. Some
 *    webserver provide Cache-Control to prevent caching.
 *
 * Usage:
 * This software synchronises your computer clock only when you issue
 * it with --synctime. By default, it only display the webserver's clock.
 */
#ifdef _MSC_VER
#ifndef _CRT_SECURE_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS /* for _snprintf(), fopen(), gmtime(),
                                   localtime(), sscanf() */
#endif
#endif

#include <stdio.h>
#include <string.h>
#include <time.h>

#include <curl/curl.h>

#ifdef _WIN32
#if (defined(_WIN32_WINNT) && (_WIN32_WINNT >= 0x0602)) || \
  defined(WINAPI_FAMILY)
#  include <winapifamily.h>
#  if WINAPI_FAMILY_PARTITION(WINAPI_PARTITION_APP) && \
     !WINAPI_FAMILY_PARTITION(WINAPI_PARTITION_DESKTOP)
#    define CURL_WINDOWS_UWP
#  endif
#include <windows.h>
#endif
#endif

#if defined(_MSC_VER) && (_MSC_VER < 1900)
#define snprintf _snprintf
#endif

#define SYNCTIME_UA "synctime/1.0"

struct conf {
  char http_proxy[256];
  char proxy_user[256];
  char timeserver[256];
};

static int ShowAllHeader;
static int AutoSyncTime;
#if defined(_WIN32) && !defined(CURL_WINDOWS_UWP)
static SYSTEMTIME SYSTime;
static SYSTEMTIME LOCALTime;

static const char *DayStr[] = {
  "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"
};
static const char *MthStr[] = {
  "Jan", "Feb", "Mar", "Apr", "May", "Jun",
  "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
};
#endif

static size_t write_cb(void *ptr, size_t size, size_t nmemb, void *stream)
{
  fwrite(ptr, size, nmemb, stream);
  return nmemb * size;
}

/* Remember: do not assume headers are passed on null terminated! */
static size_t SyncTime_CURL_WriteHeader(void *ptr, size_t size, size_t nmemb,
                                        void *stream)
{
  (void)stream;

  if(ShowAllHeader == 1)
    fprintf(stderr, "%.*s", (int)nmemb, (char *)ptr);

  if((nmemb >= 5) && !strncmp((const char *)ptr, "Date:", 5)) {
    if(ShowAllHeader == 0)
      fprintf(stderr, "HTTP Server. %.*s", (int)nmemb, (char *)ptr);

    if(AutoSyncTime == 1) {
#if defined(_WIN32) && !defined(CURL_WINDOWS_UWP)
      char TmpStr1[26], TmpStr2[26];
      int RetVal = 0;
      char *field = ptr;
      *TmpStr1 = 0;
      *TmpStr2 = 0;
      if(nmemb && (field[nmemb] == '\n')) {
        field[nmemb] = 0; /* null terminated */
        RetVal = sscanf(field, "Date: %25s %hu %25s %hu %hu:%hu:%hu",
                        TmpStr1, &SYSTime.wDay, TmpStr2, &SYSTime.wYear,
                        &SYSTime.wHour, &SYSTime.wMinute,
                        &SYSTime.wSecond);
      }

      if(RetVal == 7) {
        int i;
        SYSTime.wMilliseconds = 500;  /* adjust to midpoint, 0.5 sec */
        for(i = 0; i < 12; i++) {
          if(strcmp(MthStr[i], TmpStr2) == 0) {
            SYSTime.wMonth = (WORD)(i + 1);
            break;
          }
        }
        AutoSyncTime = 3;  /* Computer clock is adjusted */
      }
      else {
        AutoSyncTime = 0;  /* Error in sscanf() fields conversion */
      }
#endif
    }
  }

  if((nmemb >= 12) && !strncmp((const char *)ptr, "X-Cache: HIT", 12)) {
    fprintf(stderr, "ERROR: HTTP Server data is cached."
            " Server Date is no longer valid.\n");
    AutoSyncTime = 0;
  }
  return nmemb * size;
}

static void SyncTime_CURL_Init(CURL *curl, const char *proxy_port,
                               const char *proxy_user_password)
{
  if(strlen(proxy_port) > 0)
    curl_easy_setopt(curl, CURLOPT_PROXY, proxy_port);

  if(strlen(proxy_user_password) > 0)
    curl_easy_setopt(curl, CURLOPT_PROXYUSERPWD, proxy_user_password);

  curl_easy_setopt(curl, CURLOPT_USERAGENT, SYNCTIME_UA);
  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_cb);
  curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, SyncTime_CURL_WriteHeader);
}

static CURLcode SyncTime_CURL_FetchHead(CURL *curl, const char *URL_Str)
{
  CURLcode result;

  curl_easy_setopt(curl, CURLOPT_NOBODY, 1L);
  curl_easy_setopt(curl, CURLOPT_URL, URL_Str);

  result = curl_easy_perform(curl);

  return result; /* CURLE_OK */
}

static void showUsage(void)
{
  fprintf(stderr, "synctime: Synchronising computer clock with time server"
          " using HTTP protocol.\n");
  fprintf(stderr, "Usage   : synctime [Option]\n");
  fprintf(stderr, "Options :\n");
  fprintf(stderr, " --server=WEBSERVER        Use this time server instead"
          " of default.\n");
  fprintf(stderr, " --showall                 Show all HTTP header.\n");
  fprintf(stderr, " --synctime                Synchronising computer clock"
          " with time server.\n");
  fprintf(stderr, " --proxy-user=USER[:PASS]  Set proxy username and"
          " password.\n");
  fprintf(stderr, " --proxy=HOST[:PORT]       Use HTTP proxy on given"
          " port.\n");
  fprintf(stderr, " --help                    Print this help.\n");
  fprintf(stderr, "\n");
}

int main(int argc, const char *argv[])
{
  CURLcode result;
  CURL *curl;
  struct conf conf;
  int RetValue;

  ShowAllHeader = 0;  /* Do not show HTTP Header */
  AutoSyncTime = 0;   /* Do not synchronise computer clock */
  RetValue = 0;       /* Successful Exit */

  memset(&conf, 0, sizeof(conf));

  if(argc > 1) {
    int OptionIndex = 1;
    while(OptionIndex < argc) {
      if(strncmp(argv[OptionIndex], "--server=", 9) == 0)
        snprintf(conf.timeserver, sizeof(conf.timeserver) - 1, "%s",
                 &argv[OptionIndex][9]);

      if(strcmp(argv[OptionIndex], "--showall") == 0)
        ShowAllHeader = 1;

      if(strcmp(argv[OptionIndex], "--synctime") == 0)
        AutoSyncTime = 1;

      if(strncmp(argv[OptionIndex], "--proxy-user=", 13) == 0)
        snprintf(conf.proxy_user, sizeof(conf.proxy_user) - 1, "%s",
                 &argv[OptionIndex][13]);

      if(strncmp(argv[OptionIndex], "--proxy=", 8) == 0)
        snprintf(conf.http_proxy, sizeof(conf.http_proxy) - 1, "%s",
                 &argv[OptionIndex][8]);

      if((strcmp(argv[OptionIndex], "--help") == 0) ||
         (strcmp(argv[OptionIndex], "/?") == 0)) {
        showUsage();
        return 0;
      }
      OptionIndex++;
    }
  }

  if(*conf.timeserver == 0)  /* Use default server for time information */
    snprintf(conf.timeserver, sizeof(conf.timeserver) - 1, "%s",
             "https://www.ntp.org/");

  /* Init CURL before usage */
  result = curl_global_init(CURL_GLOBAL_ALL);
  if(result != CURLE_OK)
    return (int)result;

  curl = curl_easy_init();
  if(curl) {
    struct tm *lt;
    struct tm *gmt;
    time_t tt;
    time_t tt_local;
    time_t tt_gmt;
    double tzonediffFloat;
    int tzonediffWord;
    char timeBuf[61];
    char tzoneBuf[16];

    SyncTime_CURL_Init(curl, conf.http_proxy, conf.proxy_user);

    /* Calculating time diff between GMT and localtime */
    tt       = time(0);
    lt       = localtime(&tt);
    tt_local = mktime(lt);
    gmt      = gmtime(&tt);
    tt_gmt   = mktime(gmt);
    tzonediffFloat = difftime(tt_local, tt_gmt);
    tzonediffWord = (int)(tzonediffFloat / 3600.0);

    if(tzonediffWord == (int)(tzonediffFloat / 3600.0))
      snprintf(tzoneBuf, sizeof(tzoneBuf), "%+03d'00'", tzonediffWord);
    else
      snprintf(tzoneBuf, sizeof(tzoneBuf), "%+03d'30'", tzonediffWord);

#if defined(_WIN32) && !defined(CURL_WINDOWS_UWP)
    /* Get current system time and local time */
    GetSystemTime(&SYSTime);
    GetLocalTime(&LOCALTime);
    snprintf(timeBuf, 60, "%s, %02d %s %04d %02d:%02d:%02d.%03d, ",
             DayStr[LOCALTime.wDayOfWeek], LOCALTime.wDay,
             MthStr[LOCALTime.wMonth - 1], LOCALTime.wYear, LOCALTime.wHour,
             LOCALTime.wMinute, LOCALTime.wSecond, LOCALTime.wMilliseconds);
#endif

    fprintf(stderr, "Fetch: %s\n\n", conf.timeserver);
    fprintf(stderr, "Before HTTP. Date: %s%s\n\n", timeBuf, tzoneBuf);

    /* HTTP HEAD command to the Webserver */
    SyncTime_CURL_FetchHead(curl, conf.timeserver);

#if defined(_WIN32) && !defined(CURL_WINDOWS_UWP)
    GetLocalTime(&LOCALTime);
    snprintf(timeBuf, 60, "%s, %02d %s %04d %02d:%02d:%02d.%03d, ",
             DayStr[LOCALTime.wDayOfWeek], LOCALTime.wDay,
             MthStr[LOCALTime.wMonth - 1], LOCALTime.wYear, LOCALTime.wHour,
             LOCALTime.wMinute, LOCALTime.wSecond, LOCALTime.wMilliseconds);
    fprintf(stderr, "\nAfter  HTTP. Date: %s%s\n", timeBuf, tzoneBuf);

    if(AutoSyncTime == 3) {
      /* Synchronising computer clock */
      if(!SetSystemTime(&SYSTime)) {  /* Set system time */
        fprintf(stderr, "ERROR: Unable to set system time.\n");
        RetValue = 1;
      }
      else {
        /* Successfully re-adjusted computer clock */
        GetLocalTime(&LOCALTime);
        snprintf(timeBuf, 60, "%s, %02d %s %04d %02d:%02d:%02d.%03d, ",
                 DayStr[LOCALTime.wDayOfWeek], LOCALTime.wDay,
                 MthStr[LOCALTime.wMonth - 1], LOCALTime.wYear,
                 LOCALTime.wHour, LOCALTime.wMinute, LOCALTime.wSecond,
                 LOCALTime.wMilliseconds);
        fprintf(stderr, "\nNew System's Date: %s%s\n", timeBuf, tzoneBuf);
      }
    }
#endif

    /* Cleanup before exit */
    memset(&conf, 0, sizeof(conf));
    curl_easy_cleanup(curl);
  }

  curl_global_cleanup();

  return RetValue;
}
