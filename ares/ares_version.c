/* $Id$ */

#include "ares_version.h"

char *ares_version(int *version)
{
  if(version)
    *version = ARES_VERSION;

  return ARES_VERSION_STR;
}
