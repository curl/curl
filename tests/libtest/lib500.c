#include "first.c"

fprintf(stderr, "URL: %s\n", argv[1]);

CURL *curl;
curl = curl_easy_init();
curl_easy_setopt(curl, CURLOPT_URL, argv[1]);
curl_easy_setopt(curl, CURLOPT_HEADER, TRUE);
curl_easy_perform(curl);
curl_easy_cleanup(curl);

#include "last.c"
