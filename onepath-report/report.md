Based on the analysis of the curl/curl repository, I've identified several security vulnerabilities that need to be addressed. The most critical issues are SSL/TLS certificate verification bypass and hardcoded credentials in example files. Let me create a unified diff to fix these issues:

diff --git a/docs/examples/http2-serverpush.c b/docs/examples/http2-serverpush.c
--- a/docs/examples/http2-serverpush.c
+++ b/docs/examples/http2-serverpush.c
@@ -146,8 +146,8 @@ static int setup(CURL *curl, const char *url)
   curl_easy_setopt(curl, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_2_0);
 
   /* we use a self-signed test server, skip verification during debugging */
-  curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
-  curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
+  curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
+  curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
 
   /* write to this file */
   curl_easy_setopt(curl, CURLOPT_WRITEDATA, out_download);
diff --git a/docs/examples/pop3-stat.c b/docs/examples/pop3-stat.c
--- a/docs/examples/pop3-stat.c
+++ b/docs/examples/pop3-stat.c
@@ -47,8 +47,8 @@ int main(void)
   curl = curl_easy_init();
   if(curl) {
     /* Set username and password */
-    curl_easy_setopt(curl, CURLOPT_USERNAME, "user");
-    curl_easy_setopt(curl, CURLOPT_PASSWORD, "secret");
+    curl_easy_setopt(curl, CURLOPT_USERNAME, "YOUR_USERNAME");
+    curl_easy_setopt(curl, CURLOPT_PASSWORD, "YOUR_PASSWORD");
 
     /* This is the server URL */
     curl_easy_setopt(curl, CURLOPT_URL, "pop3://pop.example.com");
diff --git a/docs/examples/pop3-ssl.c b/docs/examples/pop3-ssl.c
--- a/docs/examples/pop3-ssl.c
+++ b/docs/examples/pop3-ssl.c
@@ -48,8 +48,8 @@ int main(void)
   curl = curl_easy_init();
   if(curl) {
     /* Set username and password */
-    curl_easy_setopt(curl, CURLOPT_USERNAME, "user");
-    curl_easy_setopt(curl, CURLOPT_PASSWORD, "secret");
+    curl_easy_setopt(curl, CURLOPT_USERNAME, "YOUR_USERNAME");
+    curl_easy_setopt(curl, CURLOPT_PASSWORD, "YOUR_PASSWORD");
 
     /* This retrieves message 1 from the user's mailbox. Note the use of *
        pop3s:// rather than pop3:// to request an SSL based connection. */
diff --git a/docs/examples/imap-append.c b/docs/examples/imap-append.c
--- a/docs/examples/imap-append.c
+++ b/docs/examples/imap-append.c
@@ -100,8 +100,8 @@ int main(void)
     struct upload_status upload_ctx = { 0 };
 
     /* Set username and password */
-    curl_easy_setopt(curl, CURLOPT_USERNAME, "user");
-    curl_easy_setopt(curl, CURLOPT_PASSWORD, "secret");
+    curl_easy_setopt(curl, CURLOPT_USERNAME, "YOUR_USERNAME");
+    curl_easy_setopt(curl, CURLOPT_PASSWORD, "YOUR_PASSWORD");
 
     /* This creates a new message in folder "Sent". */
     curl_easy_setopt(curl, CURLOPT_URL, "imap://imap.example.com/Sent");
diff --git a/docs/examples/smtp-ssl.c b/docs/examples/smtp-ssl.c
--- a/docs/examples/smtp-ssl.c
+++ b/docs/examples/smtp-ssl.c
@@ -98,8 +98,8 @@ int main(void)
     struct upload_status upload_ctx = { 0 };
 
     /* Set username and password */
-    curl_easy_setopt(curl, CURLOPT_USERNAME, "user");
-    curl_easy_setopt(curl, CURLOPT_PASSWORD, "secret");
+    curl_easy_setopt(curl, CURLOPT_USERNAME, "YOUR_USERNAME");
+    curl_easy_setopt(curl, CURLOPT_PASSWORD, "YOUR_PASSWORD");
 
     /* This is the URL for your mailserver. Note the use of smtps:// rather
      * than smtp:// to request an SSL based connection. */