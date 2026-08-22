#include <curl/curl.h>
/* !checksrc! disable BANNEDFUNC all */
/* !checksrc! disable COPYRIGHT all */
/* !checksrc! disable UNUSEDIGNORE all */
#line 40 "docs/libcurl/opts/CURLSHOPT_USERDATA.md"
struct secrets {
  void *custom;
};

int main(void)
{
  CURLSHcode sh;
  struct secrets private_stuff;
  CURLSH *share = curl_share_init();
  sh = curl_share_setopt(share, CURLSHOPT_USERDATA, &private_stuff);
  if(sh)
    printf("Error: %s\n", curl_share_strerror(sh));
}
