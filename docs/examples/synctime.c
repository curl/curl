/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2020, Daniel Stenberg, <daniel@haxx.se>, et al.
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
 ***************************************************************************/
/* <DESC>
 * Set your system time from a remote HTTP server's Date: header.
 * </DESC>
 */
/* This example code only builds as-is on Windows.
 *
 * While Unix/Linux user, you do not need this software.
 * You can achieve the same result as synctime using curl, awk and date.
 * Set proxy as according to your network, but beware of proxy Cache-Control.
 *
 * To set your system clock, root access is required.
 * # date -s "`curl -sI https://nist.time.gov/timezone.cgi?UTC/s/0 \
 *        | awk -F': ' '/Date: / {print $2}'`"
 *
 * To view remote webserver date and time.
 * $ curl -sI https://nist.time.gov/timezone.cgi?UTC/s/0 \
 *        | awk -F': ' '/Date: / {print $2}'
 *
 * Synchronising your computer clock via Internet time server usually relies
 * on DAYTIME, TIME, or NTP protocols. These protocols provide good accurate
 * time synchronisation but it does not work very well through a
 * firewall/proxy. Some adjustment has to be made to the firewall/proxy for
 * these protocols to work properly.
 *
 * There is an indirect method. Since most webserver provide server time in
 * their HTTP header, therefore you could synchronise your computer clock
 * using HTTP protocol which has no problem with firewall/proxy.
 *
 * For this software to work, you should take note of these items.
 * 1. Your firewall/proxy must allow your computer to surf internet.
 * 2. Webserver system time must in sync with the NTP time server,
 *    or at least provide an accurate time keeping.
 * 3. Webserver HTTP header does not provide the milliseconds units,
 *    so there is no way to get very accurate time.
 * 4. This software could only provide an accuracy of +- a few seconds,
 *    as Round-Trip delay time is not taken into consideration.
 *    Compensation of network, firewall/proxy delay cannot be simply divide
 *    the Round-Trip delay time by half.
 * 5. Win32 SetSystemTime() API will set your computer clock according to
 *    GMT/UTC time. Therefore your computer timezone must be properly set.
 * 6. Webserver data should not be cached by the proxy server. Some
 *    webserver provide Cache-Control to prevent caching.
 *
 * References:
 * https://web.archive.org/web/20100228012139/ \
 *    tf.nist.gov/timefreq/service/its.htm
 * https://web.archive.org/web/20100409024302/ \
 *    tf.nist.gov/timefreq/service/firewall.htm
 *
 * Usage:
 * This software will synchronise your computer clock only when you issue
 * it with --synctime. By default, it only display the webserver's clock.
 *
 * Written by: Frank (contributed to libcurl)
 *
 * THE SOFTWARE IS PROVIDED "AS-IS" AND WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS, IMPLIED OR OTHERWISE, INCLUDING WITHOUT LIMITATION, ANY
 * WARRANTY OF MERCHANTABILITY OR FITNESS FOR A PARTICULAR PURPOSE.
 *
 * IN NO EVENT SHALL THE AUTHOR OF THIS SOFTWARE BE LIABLE FOR
 * ANY SPECIAL, INCIDENTAL, INDIRECT OR CONSEQUENTIAL DAMAGES OF ANY KIND,
 * OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS,
 * WHETHER OR NOT ADVISED OF THE POSSIBILITY OF DAMAGE, AND ON ANY THEORY OF
 * LIABILITY, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE
 * OF THIS SOFTWARE.
 *
 */

#include <stdio.h>
#include <time.h>
#ifndef __CYGWIN__
#include <winsock2.h>
#include <windows.h>
#endif
#include <curl/curl.h>


#define MAX_STRING              256
#define MAX_STRING1             MAX_STRING + 1

#define SYNCTIME_UA "synctime/1.0"

typedef struct
{
  char http_proxy[MAX_STRING1];
  char proxy_user[MAX_STRING1];
  char timeserver[MAX_STRING1];
} conf_t;

const char DefaultTimeServer[3][MAX_STRING1] =
{
  "https://nist.time.gov/",
  "https://www.google.com/"
};

const char *DayStr[] = {"Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"};
const char *MthStr[] = {"Jan", "Feb", "Mar", "Apr", "May", "Jun",
                        "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};

int  ShowAllHeader;
int  AutoSyncTime;
SYSTEMTIME SYSTime;
SYSTEMTIME LOCALTime;

#define HTTP_COMMAND_HEAD       0
#define HTTP_COMMAND_GET        1


size_t SyncTime_CURL_WriteOutput(void *ptr, size_t size, size_t nmemb,
                                 void *stream)
{
  fwrite(ptr, size, nmemb, stream);
  return (nmemb*size);
}

size_t SyncTime_CURL_WriteHeader(void *ptr, size_t size, size_t nmemb,
                                 void *stream)
{
  char  TmpStr1[26], TmpStr2[26];

  (void)stream;

  if(ShowAllHeader == 1)
    fprintf(stderr, "%s", (char *)(ptr));

  if(strncmp((char *)(ptr), "Date:", 5) == 0) {
    if(ShowAllHeader == 0)
      fprintf(stderr, "HTTP Server. %s", (char *)(ptr));

    if(AutoSyncTime == 1) {
      *TmpStr1 = 0;
      *TmpStr2 = 0;
      if(strlen((char *)(ptr)) > 50) /* Can prevent buffer overflow to
                                         TmpStr1 & 2? */
        AutoSyncTime = 0;
      else {
        int RetVal = sscanf((char *)(ptr), "Date: %s %hu %s %hu %hu:%hu:%hu",
                            TmpStr1, &SYSTime.wDay, TmpStr2, &SYSTime.wYear,
                            &SYSTime.wHour, &SYSTime.wMinute,
                            &SYSTime.wSecond);

        if(RetVal == 7) {
          int i;
          SYSTime.wMilliseconds = 500;    /* adjust to midpoint, 0.5 sec */
          for(i = 0; i<12; i++) {
            if(strcmp(MthStr[i], TmpStr2) == 0) {
              SYSTime.wMonth = i + 1;
              break;
            }
          }
          AutoSyncTime = 3;       /* Computer clock will be adjusted */
        }
        else {
          AutoSyncTime = 0;       /* Error in sscanf() fields conversion */
        }
      }
    }
  }

  if(strncmp((char *)(ptr), "X-Cache: HIT", 12) == 0) {
    fprintf(stderr, "ERROR: HTTP Server data is cached."
            " Server Date is no longer valid.\n");
    AutoSyncTime = 0;
  }
  return (nmemb*size);
}

void SyncTime_CURL_Init(CURL *curl, char *proxy_port,
                        char *proxy_user_password)
{
  if(strlen(proxy_port) > 0)
    curl_easy_setopt(curl, CURLOPT_PROXY, proxy_port);

  if(strlen(proxy_user_password) > 0)
    curl_easy_setopt(curl, CURLOPT_PROXYUSERPWD, proxy_user_password);

#ifdef SYNCTIME_UA
  curl_easy_setopt(curl, CURLOPT_USERAGENT, SYNCTIME_UA);
#endif
  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, *SyncTime_CURL_WriteOutput);
  curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, *SyncTime_CURL_WriteHeader);
}

int SyncTime_CURL_Fetch(CURL *curl, char *URL_Str, char *OutFileName,
                        int HttpGetBody)
{
  FILE *outfile;
  CURLcode res;

  outfile = NULL;
  if(HttpGetBody == HTTP_COMMAND_HEAD)
    curl_easy_setopt(curl, CURLOPT_NOBODY, 1L);
  else {
    outfile = fopen(OutFileName, "wb");
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, outfile);
  }

  curl_easy_setopt(curl, CURLOPT_URL, URL_Str);
  res = curl_easy_perform(curl);
  if(outfile != NULL)
    fclose(outfile);
  return res;  /* (CURLE_OK) */
}

void showUsage(void)
{
  fprintf(stderr, "SYNCTIME: Synchronising computer clock with time server"
          " using HTTP protocol.\n");
  fprintf(stderr, "Usage   : SYNCTIME [Option]\n");
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
  return;
}

int conf_init(conf_t *conf)
{
  int i;

  *conf->http_proxy       = 0;
  for(i = 0; i<MAX_STRING1; i++)
    conf->proxy_user[i]     = 0;    /* Clean up password from memory */
  *conf->timeserver       = 0;
  return 1;
}

int main(int argc, char *argv[])
{
  CURL    *curl;
  conf_t  conf[1];
  int     RetValue;

  ShowAllHeader   = 0;    /* Do not show HTTP Header */
  AutoSyncTime    = 0;    /* Do not synchronise computer clock */
  RetValue        = 0;    /* Successful Exit */
  conf_init(conf);

  if(argc > 1) {
    int OptionIndex = 0;
    while(OptionIndex < argc) {
      if(strncmp(argv[OptionIndex], "--server=", 9) == 0)
        snprintf(conf->timeserver, MAX_STRING, "%s", &argv[OptionIndex][9]);

      if(strcmp(argv[OptionIndex], "--showall") == 0)
        ShowAllHeader = 1;

      if(strcmp(argv[OptionIndex], "--synctime") == 0)
        AutoSyncTime = 1;

      if(strncmp(argv[OptionIndex], "--proxy-user=", 13) == 0)
        snprintf(conf->proxy_user, MAX_STRING, "%s", &argv[OptionIndex][13]);

      if(strncmp(argv[OptionIndex], "--proxy=", 8) == 0)
        snprintf(conf->http_proxy, MAX_STRING, "%s", &argv[OptionIndex][8]);

      if((strcmp(argv[OptionIndex], "--help") == 0) ||
          (strcmp(argv[OptionIndex], "/?") == 0)) {
        showUsage();
        return 0;
      }
      OptionIndex++;
    }
  }

  if(*conf->timeserver == 0)     /* Use default server for time information */
    snprintf(conf->timeserver, MAX_STRING, "%s", DefaultTimeServer[0]);

  /* Init CURL before usage */
  curl_global_init(CURL_GLOBAL_ALL);
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

    SyncTime_CURL_Init(curl, conf->http_proxy, conf->proxy_user);

    /* Calculating time diff between GMT and localtime */
    tt       = time(0);
    lt       = localtime(&tt);
    tt_local = mktime(lt);
    gmt      = gmtime(&tt);
    tt_gmt   = mktime(gmt);
    tzonediffFloat = difftime(tt_local, tt_gmt);
    tzonediffWord  = (int)(tzonediffFloat/3600.0);

    if((double)(tzonediffWord * 3600) == tzonediffFloat)
      snprintf(tzoneBuf, 15, "%+03d'00'", tzonediffWord);
    else
      snprintf(tzoneBuf, 15, "%+03d'30'", tzonediffWord);

    /* Get current system time and local time */
    GetSystemTime(&SYSTime);
    GetLocalTime(&LOCALTime);
    snprintf(timeBuf, 60, "%s, %02d %s %04d %02d:%02d:%02d.%03d, ",
             DayStr[LOCALTime.wDayOfWeek], LOCALTime.wDay,
             MthStr[LOCALTime.wMonth-1], LOCALTime.wYear,
             LOCALTime.wHour, LOCALTime.wMinute, LOCALTime.wSecond,
             LOCALTime.wMilliseconds);

    fprintf(stderr, "Fetch: %s\n\n", conf->timeserver);
    fprintf(stderr, "Before HTTP. Date: %s%s\n\n", timeBuf, tzoneBuf);

    /* HTTP HEAD command to the Webserver */
    SyncTime_CURL_Fetch(curl, conf->timeserver, "index.htm",
                        HTTP_COMMAND_HEAD);

    GetLocalTime(&LOCALTime);
    snprintf(timeBuf, 60, "%s, %02d %s %04d %02d:%02d:%02d.%03d, ",
             DayStr[LOCALTime.wDayOfWeek], LOCALTime.wDay,
             MthStr[LOCALTime.wMonth-1], LOCALTime.wYear,
             LOCALTime.wHour, LOCALTime.wMinute, LOCALTime.wSecond,
             LOCALTime.wMilliseconds);
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
                 MthStr[LOCALTime.wMonth-1], LOCALTime.wYear,
                 LOCALTime.wHour, LOCALTime.wMinute, LOCALTime.wSecond,
                 LOCALTime.wMilliseconds);
        fprintf(stderr, "\nNew System's Date: %s%s\n", timeBuf, tzoneBuf);
      }
    }

    /* Cleanup before exit */
    conf_init(conf);
    curl_easy_cleanup(curl);
  }
  return RetValue;
}
