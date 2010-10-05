/*****************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 *
 * Upload to FTP, resuming failed transfers
 *
 * Compile for MinGW like this:
 *  gcc -Wall -pedantic -std=c99 ftpuploadwithresume.c -o ftpuploadresume.exe
 *  -lcurl -lmsvcr70
 *
 * Written by Philip Bock
 */

#include <stdlib.h>
#include <stdio.h>

#include <curl/curl.h>

#if defined(_MSC_VER) && (_MSC_VER < 1300)
#  error _snscanf requires MSVC 7.0 or later.
#endif

/* The MinGW headers are missing a few Win32 function definitions,
   you shouldn't need this if you use VC++ */
#ifdef __MINGW32__
int __cdecl _snscanf(const char * input, size_t length, const char * format, ...);
#endif


/* parse headers for Content-Length */
size_t getcontentlengthfunc(void *ptr, size_t size, size_t nmemb, void *stream)
{
  int r;
  long len = 0;

  /* _snscanf() is Win32 specific */
  r = _snscanf(ptr, size * nmemb, "Content-Length: %ld\n", &len);

  if (r) /* Microsoft: we don't read the specs */
    *((long *) stream) = len;

  return size * nmemb;
}

/* discard downloaded data */
size_t discardfunc(void *ptr, size_t size, size_t nmemb, void *stream)
{
  return size * nmemb;
}

/* read data to upload */
size_t readfunc(void *ptr, size_t size, size_t nmemb, void *stream)
{
  FILE *f = stream;
  size_t n;

  if (ferror(f))
    return CURL_READFUNC_ABORT;

  n = fread(ptr, size, nmemb, f) * size;

  return n;
}


int upload(CURL *curlhandle, const char * remotepath, const char * localpath,
           long timeout, long tries)
{
  FILE *f;
  long uploaded_len = 0;
  CURLcode r = CURLE_GOT_NOTHING;
  int c;

  f = fopen(localpath, "rb");
  if (f == NULL) {
    perror(NULL);
    return 0;
  }

  curl_easy_setopt(curlhandle, CURLOPT_UPLOAD, 1L);

  curl_easy_setopt(curlhandle, CURLOPT_URL, remotepath);

  if (timeout)
    curl_easy_setopt(curlhandle, CURLOPT_FTP_RESPONSE_TIMEOUT, timeout);

  curl_easy_setopt(curlhandle, CURLOPT_HEADERFUNCTION, getcontentlengthfunc);
  curl_easy_setopt(curlhandle, CURLOPT_HEADERDATA, &uploaded_len);

  curl_easy_setopt(curlhandle, CURLOPT_WRITEFUNCTION, discardfunc);

  curl_easy_setopt(curlhandle, CURLOPT_READFUNCTION, readfunc);
  curl_easy_setopt(curlhandle, CURLOPT_READDATA, f);

  curl_easy_setopt(curlhandle, CURLOPT_FTPPORT, "-"); /* disable passive mode */
  curl_easy_setopt(curlhandle, CURLOPT_FTP_CREATE_MISSING_DIRS, 1L);

  curl_easy_setopt(curlhandle, CURLOPT_VERBOSE, 1L);

  for (c = 0; (r != CURLE_OK) && (c < tries); c++) {
    /* are we resuming? */
    if (c) { /* yes */
      /* determine the length of the file already written */

      /*
       * With NOBODY and NOHEADER, libcurl will issue a SIZE
       * command, but the only way to retrieve the result is
       * to parse the returned Content-Length header. Thus,
       * getcontentlengthfunc(). We need discardfunc() above
       * because HEADER will dump the headers to stdout
       * without it.
       */
      curl_easy_setopt(curlhandle, CURLOPT_NOBODY, 1L);
      curl_easy_setopt(curlhandle, CURLOPT_HEADER, 1L);

      r = curl_easy_perform(curlhandle);
      if (r != CURLE_OK)
        continue;

      curl_easy_setopt(curlhandle, CURLOPT_NOBODY, 0L);
      curl_easy_setopt(curlhandle, CURLOPT_HEADER, 0L);

      fseek(f, uploaded_len, SEEK_SET);

      curl_easy_setopt(curlhandle, CURLOPT_APPEND, 1L);
    }
    else { /* no */
      curl_easy_setopt(curlhandle, CURLOPT_APPEND, 0L);
    }

    r = curl_easy_perform(curlhandle);
  }

  fclose(f);

  if (r == CURLE_OK)
    return 1;
  else {
    fprintf(stderr, "%s\n", curl_easy_strerror(r));
    return 0;
  }
}

int main(int c, char **argv)
{
  CURL *curlhandle = NULL;

  curl_global_init(CURL_GLOBAL_ALL);
  curlhandle = curl_easy_init();

  upload(curlhandle, "ftp://user:pass@example.com/path/file", "C:\\file", 0, 3);

  curl_easy_cleanup(curlhandle);
  curl_global_cleanup();

  return 0;
}
