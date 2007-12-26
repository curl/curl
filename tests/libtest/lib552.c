/*****************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * $Id$
 *
 * argv1 = URL
 * argv2 = proxy with embedded user+password
 */

#include "test.h"

struct data {
  char trace_ascii; /* 1 or 0 */
};

static
void dump(const char *text,
          FILE *stream, unsigned char *ptr, size_t size,
          char nohex)
{
  size_t i;
  size_t c;

  unsigned int width=0x10;

  if(nohex)
    /* without the hex output, we can fit more on screen */
    width = 0x40;

  fprintf(stream, "%s, %d bytes (0x%x)\n", text, (int)size, (int)size);

  for(i=0; i<size; i+= width) {

    fprintf(stream, "%04x: ", (int)i);

    if(!nohex) {
      /* hex not disabled, show it */
      for(c = 0; c < width; c++)
        if(i+c < size)
          fprintf(stream, "%02x ", ptr[i+c]);
        else
          fputs("   ", stream);
    }

    for(c = 0; (c < width) && (i+c < size); c++) {
      /* check for 0D0A; if found, skip past and start a new line of output */
      if (nohex && (i+c+1 < size) && ptr[i+c]==0x0D && ptr[i+c+1]==0x0A) {
        i+=(c+2-width);
        break;
      }
      fprintf(stream, "%c",
              (ptr[i+c]>=0x20) && (ptr[i+c]<0x80)?ptr[i+c]:'.');
      /* check again for 0D0A, to avoid an extra \n if it's at width */
      if (nohex && (i+c+2 < size) && ptr[i+c+1]==0x0D && ptr[i+c+2]==0x0A) {
        i+=(c+3-width);
        break;
      }
    }
    fputc('\n', stream); /* newline */
  }
  fflush(stream);
}

static
int my_trace(CURL *handle, curl_infotype type,
             unsigned char *data, size_t size,
             void *userp)
{
  struct data *config = (struct data *)userp;
  const char *text;
  (void)handle; /* prevent compiler warning */

  switch (type) {
  case CURLINFO_TEXT:
    fprintf(stderr, "== Info: %s", data);
  default: /* in case a new one is introduced to shock us */
    return 0;

  case CURLINFO_HEADER_OUT:
    text = "=> Send header";
    break;
  case CURLINFO_DATA_OUT:
    text = "=> Send data";
    break;
  case CURLINFO_SSL_DATA_OUT:
    text = "=> Send SSL data";
    break;
  case CURLINFO_HEADER_IN:
    text = "<= Recv header";
    break;
  case CURLINFO_DATA_IN:
    text = "<= Recv data";
    break;
  case CURLINFO_SSL_DATA_IN:
    text = "<= Recv SSL data";
    break;
  }

  dump(text, stderr, data, size, config->trace_ascii);
  return 0;
}


static size_t current_offset = 0;
char data[70000]; /* MUST  be more than 64k OR MAX_INITIAL_POST_SIZE */

static size_t read_callback(void *ptr, size_t size, size_t nmemb, void *stream)
{
  size_t  amount = nmemb * size; /* Total bytes curl wants */
  size_t  available = sizeof data - current_offset;  /* What we have to give */
  size_t  given = amount < available ? amount : available; /* What is given */
  (void)stream;
  memcpy(ptr, data + current_offset, given);
  current_offset += given;
  return given;
}


static size_t write_callback(void *ptr, size_t size, size_t nmemb, void *stream)
{
  printf("%.*s", size * nmemb, (char *)ptr);
  (void)stream;
  return size * nmemb;
}


static curlioerr ioctl_callback(CURL * handle, int cmd, void *clientp)
{
  (void)clientp;
  if (cmd == CURLIOCMD_RESTARTREAD ) {
    printf("APPLICATION: recieved a CURLIOCMD_RESTARTREAD request\n");
    printf("APPLICATION: ** REWINDING! **\n");
    current_offset = 0;
    return CURLIOE_OK;
  }
  (void)handle;
  return CURLIOE_UNKNOWNCMD;
}



int test(char *URL)
{
  CURL *curl;
  CURLcode res;
  struct data config;
  size_t i;
  char fill[] = "test data";

  config.trace_ascii = 1; /* enable ascii tracing */

  curl = curl_easy_init();
  if(curl) {
    curl_easy_setopt(curl, CURLOPT_DEBUGFUNCTION, my_trace);
    curl_easy_setopt(curl, CURLOPT_DEBUGDATA, &config);
    /* the DEBUGFUNCTION has no effect until we enable VERBOSE */
    curl_easy_setopt(curl, CURLOPT_VERBOSE, 1);

    /* setup repeated data string */
    for (i=0; i < sizeof data; ++i)
        data[i] = fill[i % sizeof fill];

    /* Post */
    curl_easy_setopt(curl, CURLOPT_POST, 1);

    /* Setup read callback */
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, sizeof data);
    curl_easy_setopt(curl, CURLOPT_READFUNCTION, read_callback);

    /* Write callback */
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);

    /* Ioctl function */
    curl_easy_setopt(curl, CURLOPT_IOCTLFUNCTION, ioctl_callback);

    curl_easy_setopt(curl, CURLOPT_PROXY, libtest_arg2);

    curl_easy_setopt(curl, CURLOPT_URL, URL);

    /* Accept any auth. But for this bug configure proxy with DIGEST, basic might work too, not NTLM */
    curl_easy_setopt(curl, CURLOPT_PROXYAUTH, CURLAUTH_ANY);

    res = curl_easy_perform(curl);
    fprintf(stderr, "curl_east_perform = %d\n", res);

    /* always cleanup */
    curl_easy_cleanup(curl);
  }
  return 0;
}
