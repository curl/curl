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
#include "curl_setup.h"

#if defined(USE_SQLITE) && !defined(CURL_DISABLE_HTTP) && \
  !defined(CURL_DISABLE_COOKIES)

#include <sqlite3.h>

#include "urldata.h"
#include "cookie.h"
#include "cookie_db.h"
#include "curl_trc.h"
#include "llist.h"
#include "curlx/strdup.h"

/*
 * The SQLite cookie store keeps one row per cookie. The in-memory cookies of
 * the CookieInfo are loaded from it and every cookie received from a server
 * is written through to it right away, so several handles and processes can
 * share one store and see each others cookies. "PRAGMA data_version" tells
 * when another connection changed the database, the cookies are then
 * reloaded before they are used.
 *
 * A row is loaded by formatting it as a cookie file line, preceded by a
 * "#curl:" attribute line when needed, and passing it to Curl_cookie_add().
 * The rows thereby get the same checks as the lines of a cookie file.
 */

struct cookie_db {
  sqlite3 *h;
  char *path;
  sqlite3_stmt *st_select;
  sqlite3_stmt *st_store;
  sqlite3_stmt *st_remove;
  sqlite3_stmt *st_version;
  int data_version;
  BIT(loaded);  /* the cookies were loaded from the database */
};

static const char cookie_db_schema[] =
  "CREATE TABLE IF NOT EXISTS cookies ("
  "domain TEXT NOT NULL, "
  "tailmatch INTEGER NOT NULL, "
  "path TEXT NOT NULL, "
  "secure INTEGER NOT NULL, "
  "httponly INTEGER NOT NULL, "
  "expires INTEGER NOT NULL, "
  "name TEXT NOT NULL, "
  "value TEXT NOT NULL, "
  "samesite INTEGER NOT NULL DEFAULT 0, "
  "partkey TEXT NOT NULL DEFAULT '', "
  "PRIMARY KEY (domain, tailmatch, path, name, partkey))";

/* in the order the cookies were stored, the way a cookie file is read */
static const char cookie_db_select_sql[] =
  "SELECT domain, tailmatch, path, secure, httponly, expires, name, value, "
  "samesite, partkey FROM cookies WHERE expires = 0 OR expires >= ?1 "
  "ORDER BY rowid";

static const char cookie_db_store_sql[] =
  "INSERT OR REPLACE INTO cookies (domain, tailmatch, path, secure, "
  "httponly, expires, name, value, samesite, partkey) "
  "VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)";

static const char cookie_db_remove_sql[] =
  "DELETE FROM cookies WHERE domain = ?1 AND tailmatch = ?2 AND "
  "path = ?3 AND name = ?4 AND partkey = ?5";

static int cookie_db_exec(struct cookie_db *db, const char *sql)
{
  return sqlite3_exec(db->h, sql, NULL, NULL, NULL);
}

static int cookie_db_data_version(struct cookie_db *db)
{
  int version = 0;
  if(sqlite3_step(db->st_version) == SQLITE_ROW)
    version = sqlite3_column_int(db->st_version, 0);
  sqlite3_reset(db->st_version);
  return version;
}

static void cookie_db_free(struct cookie_db *db)
{
  if(db) {
    /* sqlite3_finalize() accepts NULL */
    sqlite3_finalize(db->st_select);
    sqlite3_finalize(db->st_store);
    sqlite3_finalize(db->st_remove);
    sqlite3_finalize(db->st_version);
    if(db->h)
      sqlite3_close(db->h);
    curlx_free(db->path);
    curlx_free(db);
  }
}

void Curl_cookie_db_close(struct CookieInfo *ci)
{
  if(ci && ci->db) {
    cookie_db_free(ci->db);
    ci->db = NULL;
  }
}

static const char *cookie_db_text(sqlite3_stmt *st, int col)
{
  const char *s = (const char *)sqlite3_column_text(st, col);
  return s ? s : "";
}

/*
 * Add the current row of the SELECT to the in-memory cookies, as cookie file
 * lines through Curl_cookie_add(). A bad row is skipped like a bad line in a
 * cookie file.
 */
static CURLcode cookie_db_add_row(struct Curl_easy *data,
                                  struct CookieInfo *ci, sqlite3_stmt *st)
{
  /* indexed by COOKIE_SAMESITE_*, Default is written as nothing */
  static const char * const samesite[] = { NULL, "None", "Lax", "Strict" };
  const char *ss = samesite[sqlite3_column_int(st, 8) & 3];
  const char *partkey = cookie_db_text(st, 9);
  const char *domain = cookie_db_text(st, 0);
  const bool tailmatch = !!sqlite3_column_int(st, 1);
  const int flags = COOKIE_NOEXPIRE | COOKIE_SECURE | COOKIE_NOPSL;
  CURLcode result = CURLE_OK;
  char *line;

  if(ss || *partkey) {
    /* the attributes of the cookie on the next line */
    line = curl_maprintf("#curl: %s%s%s%s%s",
                         ss ? "SameSite=" : "", ss ? ss : "",
                         (ss && *partkey) ? "; " : "",
                         *partkey ? "Partitioned=" : "", partkey);
    if(!line)
      return CURLE_OUT_OF_MEMORY;
    result = Curl_cookie_add(data, ci, line, NULL, NULL, flags);
    curlx_free(line);
    if(result)
      return result;
  }
  line = curl_maprintf("%s%s%s\t%s\t%s\t%s\t%" FMT_OFF_T "\t%s\t%s",
                       sqlite3_column_int(st, 4) ? "#HttpOnly_" : "",
                       (tailmatch && (*domain != '.')) ? "." : "", domain,
                       tailmatch ? "TRUE" : "FALSE",
                       cookie_db_text(st, 2),
                       sqlite3_column_int(st, 3) ? "TRUE" : "FALSE",
                       (curl_off_t)sqlite3_column_int64(st, 5),
                       cookie_db_text(st, 6), cookie_db_text(st, 7));
  if(!line)
    return CURLE_OUT_OF_MEMORY;
  result = Curl_cookie_add(data, ci, line, NULL, NULL, flags);
  curlx_free(line);
  return (result == CURLE_OUT_OF_MEMORY) ? result : CURLE_OK;
}

/*
 * Replace the in-memory cookies with the rows of the database.
 */
static CURLcode cookie_db_load(struct Curl_easy *data, struct CookieInfo *ci)
{
  struct cookie_db *db = ci->db;
  sqlite3_stmt *st = db->st_select;
  CURLcode result = CURLE_OK;
  const bool running = ci->running;
  const bool newsession = ci->newsession;

  /* read the version first, a change made during the load is then seen */
  db->data_version = cookie_db_data_version(db);
  Curl_cookie_clearall(ci);
  /* the rows are stored cookies, not live ones. The session cookies among
     them are from this session, or were already purged when the database
     was opened */
  ci->running = FALSE;
  ci->newsession = FALSE;
  sqlite3_bind_int64(st, 1, (sqlite3_int64)time(NULL));
  while(sqlite3_step(st) == SQLITE_ROW) {
    result = cookie_db_add_row(data, ci, st);
    if(result)
      break;
  }
  sqlite3_reset(st);
  ci->running = running;
  ci->newsession = newsession;
  db->loaded = TRUE;
  CURL_TRC_M(data, "[cookies] loaded %u cookies from %s", ci->numcookies,
             db->path);
  return result;
}

CURLcode Curl_cookie_db_open(struct Curl_easy *data, struct CookieInfo *ci,
                             const char *path, bool newsession)
{
  struct cookie_db *db;
  int rc;

  if(ci->db && !strcmp(ci->db->path, path))
    return CURLE_OK; /* already open */
  Curl_cookie_db_close(ci);

  db = curlx_calloc(1, sizeof(*db));
  if(!db)
    return CURLE_OUT_OF_MEMORY;
  db->path = curlx_strdup(path);
  if(!db->path) {
    curlx_free(db);
    return CURLE_OUT_OF_MEMORY;
  }
  rc = sqlite3_open_v2(path, &db->h,
                       SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, NULL);
  if(rc != SQLITE_OK) {
    infof(data, "WARNING: failed to open cookie database \"%s\": %s", path,
          db->h ? sqlite3_errmsg(db->h) : sqlite3_errstr(rc));
    cookie_db_free(db);
    return CURLE_OK;
  }
  sqlite3_busy_timeout(db->h, 2000);
  /* readers do not block writers and vice versa */
  cookie_db_exec(db, "PRAGMA journal_mode=WAL");
  rc = cookie_db_exec(db, cookie_db_schema);
  if(rc == SQLITE_OK)
    rc = sqlite3_prepare_v2(db->h, cookie_db_select_sql, -1, &db->st_select,
                            NULL);
  if(rc == SQLITE_OK)
    rc = sqlite3_prepare_v2(db->h, cookie_db_store_sql, -1, &db->st_store,
                            NULL);
  if(rc == SQLITE_OK)
    rc = sqlite3_prepare_v2(db->h, cookie_db_remove_sql, -1, &db->st_remove,
                            NULL);
  if(rc == SQLITE_OK)
    rc = sqlite3_prepare_v2(db->h, "PRAGMA data_version", -1,
                            &db->st_version, NULL);
  if(rc != SQLITE_OK) {
    infof(data, "WARNING: cannot use cookie database \"%s\": %s", path,
          sqlite3_errmsg(db->h));
    cookie_db_free(db);
    return CURLE_OK;
  }

  if(newsession)
    /* the stored session cookies belong to a previous session */
    cookie_db_exec(db, "DELETE FROM cookies WHERE expires = 0");
  {
    /* drop expired cookies, they are not loaded anyway */
    char sql[80];
    curl_msnprintf(sql, sizeof(sql),
                   "DELETE FROM cookies WHERE expires > 0 AND expires < %"
                   FMT_OFF_T, (curl_off_t)time(NULL));
    cookie_db_exec(db, sql);
  }
  ci->db = db;
  return CURLE_OK;
}

CURLcode Curl_cookie_db_sync(struct Curl_easy *data, struct CookieInfo *ci)
{
  struct cookie_db *db = ci ? ci->db : NULL;
  if(db && (cookie_db_data_version(db) != db->data_version)) {
    CURL_TRC_M(data, "[cookies] database %s changed, reloading", db->path);
    return cookie_db_load(data, ci);
  }
  return CURLE_OK;
}

static int cookie_db_bind_key(sqlite3_stmt *st, const struct Cookie *co)
{
  int rc = sqlite3_bind_text(st, 1, co->domain, -1, SQLITE_STATIC);
  if(rc == SQLITE_OK)
    rc = sqlite3_bind_int(st, 2, co->tailmatch ? 1 : 0);
  if(rc == SQLITE_OK)
    rc = sqlite3_bind_text(st, 3, co->path ? co->path : "", -1,
                           SQLITE_STATIC);
  return rc;
}

void Curl_cookie_db_store(struct CookieInfo *ci, const struct Cookie *co)
{
  struct cookie_db *db = ci ? ci->db : NULL;
  sqlite3_stmt *st;
  int rc;

  if(!db || !co->domain || !co->name)
    return;
  st = db->st_store;
  rc = cookie_db_bind_key(st, co);
  if(rc == SQLITE_OK)
    rc = sqlite3_bind_int(st, 4, co->secure ? 1 : 0);
  if(rc == SQLITE_OK)
    rc = sqlite3_bind_int(st, 5, co->httponly ? 1 : 0);
  if(rc == SQLITE_OK)
    rc = sqlite3_bind_int64(st, 6, (sqlite3_int64)co->expires);
  if(rc == SQLITE_OK)
    rc = sqlite3_bind_text(st, 7, co->name, -1, SQLITE_STATIC);
  if(rc == SQLITE_OK)
    rc = sqlite3_bind_text(st, 8, co->value ? co->value : "", -1,
                           SQLITE_STATIC);
  if(rc == SQLITE_OK)
    rc = sqlite3_bind_int(st, 9, (int)co->samesite);
  if(rc == SQLITE_OK)
    rc = sqlite3_bind_text(st, 10, co->partkey ? co->partkey : "", -1,
                           SQLITE_STATIC);
  if(rc == SQLITE_OK)
    (void)sqlite3_step(st);
  sqlite3_reset(st);
  sqlite3_clear_bindings(st);
}

void Curl_cookie_db_remove(struct CookieInfo *ci, const struct Cookie *co)
{
  struct cookie_db *db = ci ? ci->db : NULL;
  sqlite3_stmt *st;
  int rc;

  if(!db || !co->domain || !co->name)
    return;
  st = db->st_remove;
  rc = cookie_db_bind_key(st, co);
  if(rc == SQLITE_OK)
    rc = sqlite3_bind_text(st, 4, co->name, -1, SQLITE_STATIC);
  if(rc == SQLITE_OK)
    rc = sqlite3_bind_text(st, 5, co->partkey ? co->partkey : "", -1,
                           SQLITE_STATIC);
  if(rc == SQLITE_OK)
    (void)sqlite3_step(st);
  sqlite3_reset(st);
  sqlite3_clear_bindings(st);
}

void Curl_cookie_db_clear(struct CookieInfo *ci, bool session_only)
{
  struct cookie_db *db = ci ? ci->db : NULL;
  if(db)
    cookie_db_exec(db, session_only ?
                   "DELETE FROM cookies WHERE expires = 0" :
                   "DELETE FROM cookies");
}

CURLcode Curl_cookie_db_import(struct Curl_easy *data, struct CookieInfo *ci,
                               bool files)
{
  struct cookie_db *db = ci->db;
  unsigned int i;

  if(!db || (db->loaded && !files))
    return CURLE_OK; /* nothing new to write */
  cookie_db_exec(db, "BEGIN");
  for(i = 0; i < COOKIE_HASH_SIZE; i++) {
    struct Curl_llist_node *n;
    for(n = Curl_llist_head(&ci->cookielist[i]); n; n = Curl_node_next(n))
      Curl_cookie_db_store(ci, Curl_node_elem(n));
  }
  cookie_db_exec(db, "COMMIT");
  return cookie_db_load(data, ci);
}

#endif /* USE_SQLITE && !CURL_DISABLE_HTTP && !CURL_DISABLE_COOKIES */
