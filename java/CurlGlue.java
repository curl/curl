/**
 * The curl class is a JNI wrapper for libcurl. Please bear with me, I'm no
 * true java dude (yet). Improve what you think is bad and send me the
 * updates!
 * daniel@haxx.se
 *
 * This is meant as a raw, crude and low-level interface to libcurl. If you
 * want fancy stuff, build upon this.
 */

public class CurlGlue
{
  // start of imported generated list, make a new list with
  // define2java.pl on demand
  public static final int CURLOPT_NOTHING  = 0;
  public static final int CURLOPT_FILE  = 10001;
  public static final int CURLOPT_URL  = 10002;
  public static final int CURLOPT_PORT  = 3;
  public static final int CURLOPT_PROXY  = 10004;
  public static final int CURLOPT_USERPWD  = 10005;
  public static final int CURLOPT_PROXYUSERPWD  = 10006;
  public static final int CURLOPT_RANGE  = 10007;
  public static final int CURLOPT_INFILE  = 10009;
  public static final int CURLOPT_ERRORBUFFER  = 10010;
  public static final int CURLOPT_WRITEFUNCTION  = 20011;
  public static final int CURLOPT_READFUNCTION  = 20012;
  public static final int CURLOPT_TIMEOUT  = 13;
  public static final int CURLOPT_INFILESIZE  = 14;
  public static final int CURLOPT_POSTFIELDS  = 10015;
  public static final int CURLOPT_REFERER  = 10016;
  public static final int CURLOPT_FTPPORT  = 10017;
  public static final int CURLOPT_USERAGENT  = 10018;
  public static final int CURLOPT_LOW_SPEED_LIMIT  = 19;
  public static final int CURLOPT_LOW_SPEED_TIME  = 20;
  public static final int CURLOPT_RESUME_FROM  = 21;
  public static final int CURLOPT_COOKIE  = 10022;
  public static final int CURLOPT_HTTPHEADER  = 10023;
  public static final int CURLOPT_HTTPPOST  = 10024;
  public static final int CURLOPT_SSLCERT  = 10025;
  public static final int CURLOPT_SSLCERTPASSWD  = 10026;
  public static final int CURLOPT_CRLF  = 27;
  public static final int CURLOPT_QUOTE  = 10028;
  public static final int CURLOPT_WRITEHEADER  = 10029;
  public static final int CURLOPT_COOKIEFILE  = 10031;
  public static final int CURLOPT_SSLVERSION  = 32;
  public static final int CURLOPT_TIMECONDITION  = 33;
  public static final int CURLOPT_TIMEVALUE  = 34;
  public static final int CURLOPT_HTTPREQUEST  = 10035;
  public static final int CURLOPT_CUSTOMREQUEST  = 10036;
  public static final int CURLOPT_STDERR  = 10037;
  public static final int CURLOPT_POSTQUOTE  = 10039;
  public static final int CURLOPT_WRITEINFO  = 10040;
  public static final int CURLOPT_VERBOSE  = 41;
  public static final int CURLOPT_HEADER  = 42;
  public static final int CURLOPT_NOPROGRESS  = 43;
  public static final int CURLOPT_NOBODY  = 44;
  public static final int CURLOPT_FAILONERROR  = 45;
  public static final int CURLOPT_UPLOAD  = 46;
  public static final int CURLOPT_POST  = 47;
  public static final int CURLOPT_FTPLISTONLY  = 48;
  public static final int CURLOPT_FTPAPPEND  = 50;
  public static final int CURLOPT_NETRC  = 51;
  public static final int CURLOPT_FOLLOWLOCATION  = 52;
  public static final int CURLOPT_FTPASCII  = 53;
  public static final int CURLOPT_TRANSFERTEXT  = 53;
  public static final int CURLOPT_PUT  = 54;
  public static final int CURLOPT_MUTE  = 55;
  public static final int CURLOPT_PROGRESSFUNCTION  = 20056;
  public static final int CURLOPT_PROGRESSDATA  = 10057;
  public static final int CURLOPT_AUTOREFERER  = 58;
  public static final int CURLOPT_PROXYPORT  = 59;
  public static final int CURLOPT_POSTFIELDSIZE  = 60;
  public static final int CURLOPT_HTTPPROXYTUNNEL  = 61;
  public static final int CURLOPT_INTERFACE  = 10062;
  public static final int CURLOPT_KRB4LEVEL  = 10063;
  public static final int CURLOPT_SSL_VERIFYPEER  = 64;
  public static final int CURLOPT_CAINFO  = 10065;
  public static final int CURLOPT_PASSWDFUNCTION  = 20066;
  public static final int CURLOPT_PASSWDDATA  = 10067;
  public static final int CURLOPT_MAXREDIRS  = 68;
  public static final int CURLOPT_FILETIME  = 10069;
  public static final int CURLOPT_TELNETOPTIONS  = 10070;
  public static final int CURLOPT_MAXCONNECTS  = 71;
  public static final int CURLOPT_CLOSEPOLICY  = 72;
  public static final int CURLOPT_CLOSEFUNCTION  = 20073;
  public static final int CURLOPT_FRESH_CONNECT  = 74;
  public static final int CURLOPT_FORBID_REUSE  = 75;
  public static final int CURLOPT_RANDOM_FILE  = 10076;
  public static final int CURLOPT_EGDSOCKET  = 10077;
  public static final int CURLOPT_CONNECTTIMEOUT  = 78;
  public static final int CURLOPT_HEADERFUNCTION  = 20079;
  // end of generated list

  public CurlGlue() {
    javacurl_handle = jni_init();
  }

  public void finalize() {
    jni_cleanup(javacurl_handle);
  }

  private int javacurl_handle;

  /* constructor and destructor for the libcurl handle */
  private native int jni_init();
  private native void jni_cleanup(int javacurl_handle);
  private native synchronized int jni_perform(int javacurl_handle);
  
    // Instead of varargs, we have different functions for each
  // kind of type setopt() can take
  private native int jni_setopt(int libcurl, int option, String value);
  private native int jni_setopt(int libcurl, int option, int value);
  private native int jni_setopt(int libcurl, int option, CurlWrite value);

  public native int getinfo();
  
  public int perform() {
    return jni_perform(javacurl_handle);
  }
  public int setopt(int option, int value) {
    return jni_setopt(javacurl_handle, option, value);
  }
  public int setopt(int option, String value) {
    return jni_setopt(javacurl_handle, option, value);
  }
  public int setopt(int option, CurlWrite value) {
    return jni_setopt(javacurl_handle, option, value);
  }

  static {
    System.loadLibrary("javacurl");
  }
  
}
