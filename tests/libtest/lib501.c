#include "first.c"

fprintf(stderr, "URL: %s\n", argv[1]);

CURL *curl;
CURLcode res;
curl = curl_easy_init();
curl_easy_setopt(curl, CURLOPT_HEADER, TRUE);
res = curl_easy_perform(curl);
curl_easy_cleanup(curl);

return res;
#include "last.c"
