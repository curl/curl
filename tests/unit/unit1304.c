#include <stdlib.h>
#include "curl_config.h"
#include "setup.h"

#include "netrc.h"
#include "curlcheck.h"

char login[LOGINSIZE];
char password[PASSWORDSIZE];
char filename[64];

static CURLcode unit_setup(void)
{
  password[0] = 0;
  login[0] = 0;
  return CURLE_OK;
}

static void unit_stop(void)
{
}

UNITTEST_START
  int result;

  static const char* filename1 = "log/netrc";
  memcpy(filename, filename1, strlen(filename1));

  /*
   * Test a non existent host in our netrc file.
   */
  result = Curl_parsenetrc("test.example.com", login, password, filename);
  fail_unless(result == 1, "Host not found should return 1");
  fail_unless(password[0] == 0, "password should not have been changed");
  fail_unless(login[0] == 0, "login should not have been changed");

  /*
   * Test a non existent login in our netrc file.
   */
  memcpy(login, "me", 2);
  result = Curl_parsenetrc("example.com", login, password, filename);
  fail_unless(result == 0, "Host should be found");
  fail_unless(password[0] == 0, "password should not have been changed");
  fail_unless(strncmp(login, "me", 2) == 0, "login should not have been changed");

  /*
   * Test a non existent login and host in our netrc file.
   */
  memcpy(login, "me", 2);
  result = Curl_parsenetrc("test.example.com", login, password, filename);
  fail_unless(result == 1, "Host should be found");
  fail_unless(password[0] == 0, "password should not have been changed");
  fail_unless(strncmp(login, "me", 2) == 0, "login should not have been changed");

  /*
   * Test a non existent login (substring of an existing one) in our
   * netrc file.
   */
  memcpy(login, "admi", 4);
  result = Curl_parsenetrc("example.com", login, password, filename);
  fail_unless(result == 0, "Host should be found");
  fail_unless(password[0] == 0, "password should not have been changed");
  fail_unless(strncmp(login, "admi", 4) == 0, "login should not have been changed");

  /*
   * Test a non existent login (superstring of an existing one)
   * in our netrc file.
   */
  memcpy(login, "adminn", 6);
  result = Curl_parsenetrc("example.com", login, password, filename);
  fail_unless(result == 0, "Host should be found");
  fail_unless(password[0] == 0, "password should not have been changed");
  fail_unless(strncmp(login, "adminn", 6) == 0, "login should not have been changed");

  /*
   * Test for the first existing host in our netrc file
   * with login[0] = 0.
   */
  login[0] = 0;
  result = Curl_parsenetrc("example.com", login, password, filename);
  fail_unless(result == 0, "Host should have been found");
  fail_unless(strncmp(password, "passwd", 6) == 0,
              "password should be 'passwd'");
  fail_unless(strncmp(login, "admin", 5) == 0, "login should be 'admin'");

  /*
   * Test for the first existing host in our netrc file
   * with login[0] != 0.
   */
  password[0] = 0;
  result = Curl_parsenetrc("example.com", login, password, filename);
  fail_unless(result == 0, "Host should have been found");
  fail_unless(strncmp(password, "passwd", 6) == 0,
              "password should be 'passwd'");
  fail_unless(strncmp(login, "admin", 5) == 0, "login should be 'admin'");

  /*
   * Test for the second existing host in our netrc file
   * with login[0] = 0.
   */
  password[0] = 0;
  login[0] = 0;
  result = Curl_parsenetrc("curl.example.com", login, password, filename);
  fail_unless(result == 0, "Host should have been found");
  fail_unless(strncmp(password, "none", 4) == 0,
              "password should be 'none'");
  fail_unless(strncmp(login, "none", 4) == 0, "login should be 'none'");

  /*
   * Test for the second existing host in our netrc file
   * with login[0] != 0.
   */
  password[0] = 0;
  result = Curl_parsenetrc("curl.example.com", login, password, filename);
  fail_unless(result == 0, "Host should have been found");
  fail_unless(strncmp(password, "none", 4) == 0,
              "password should be 'none'");
  fail_unless(strncmp(login, "none", 4) == 0, "login should be 'none'");

  /* TODO:
   * Test over the size limit password / login!
   * Test files with a bad format
   */
UNITTEST_STOP
