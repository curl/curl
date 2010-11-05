#include <sys/types.h>
#include <sys/xattr.h> /* include header from libc, not from libattr */
#include <string.h>
#include <curl/curl.h>
#include "xattr.h"

/* mapping table of curl metadata to extended attribute names */
static struct xattr_mapping {
  char *attr; /* name of the xattr */
  CURLINFO info;
} mappings[] = {
  /* mappings proposed by
   * http://freedesktop.org/wiki/CommonExtendedAttributes
   */
  { "user.xdg.origin.url", CURLINFO_EFFECTIVE_URL },
  { "user.mime_type", CURLINFO_CONTENT_TYPE },
  { NULL, 0 } /* last element, abort loop here */
};

/* store metadata from the curl request alongside the downloaded
 * file using extended attributes
 */
int write_xattr( CURL *curl, const char *filename )
{
  int i = 0;
  int err = 0;
  /* loop through all xattr-curlinfo pairs and abort on error */
  while ( err == 0 && mappings[i].attr != NULL ) {
    char *value = NULL;
    curl_easy_getinfo(curl, mappings[i].info, &value);
    if (value) {
      err = setxattr( filename, mappings[i].attr, value, strlen(value), 0 );
    }
    i++;
  }
  return err;
}
