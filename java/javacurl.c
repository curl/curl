
#include <curl/curl.h> /* libcurl header */
#include "CurlGlue.h"  /* the JNI-generated glue header file */

/*
 * This is a private struct allocated for every 'CurlGlue' object.
 */
struct javacurl {
  void *libcurl;
  void *whatever;
  struct writecallback {
    jmethodID mid;
    JNIEnv *java;
    jobject object;
  } write;
};

JNIEXPORT jint JNICALL Java_CurlGlue_jni_1init(JNIEnv *java,
                                               jobject myself)
{
  void *libhandle;
  struct javacurl *jcurl=NULL;

  libhandle = curl_easy_init();

  if(libhandle) {
    jcurl=(struct javacurl *)malloc(sizeof(struct javacurl));
    if(jcurl) {
      memset(jcurl, 0, sizeof(struct javacurl));
      jcurl->libcurl = libhandle;

    }
    else {
      curl_easy_cleanup(libhandle);
      return (jint)0;
    }
  }

  return (jint) jcurl; /* nasty typecast */
}

JNIEXPORT void JNICALL Java_CurlGlue_jni_1cleanup(JNIEnv *java,
                                                  jobject myself,
                                                  jint jcurl)
{
  void *handle=(void *)((struct javacurl*)jcurl)->libcurl;

  curl_easy_cleanup(handle); /* cleanup libcurl stuff */

  free((void *)jcurl); /* free the struct too */
}

/*
 * setopt() int + string
 */
JNIEXPORT jint JNICALL Java_CurlGlue_jni_1setopt__IILjava_lang_String_2
  (JNIEnv *java, jobject myself, jint jcurl, jint option, jstring value)
{
  /* get the actual string C-style */
  const char *str = (*java)->GetStringUTFChars(java, value, 0);

  void *handle = (void *)((struct javacurl*)jcurl)->libcurl;

  puts("setopt int + string");
  
  return (jint)curl_easy_setopt(handle, (CURLoption)option, str);

}

/*
 * setopt() int + int 
 */
JNIEXPORT jint JNICALL Java_CurlGlue_jni_1setopt__III
  (JNIEnv *java, jobject myself, jint jcurl, jint option, jint value)
{
  void *handle = (void *)((struct javacurl*)jcurl)->libcurl;

  puts("setopt int + int");

  return (jint)curl_easy_setopt(handle, (CURLoption)option, value);
}

static int javacurl_write_callback(void *ptr,
                                   size_t size,
                                   size_t nmemb,
                                   FILE  *stream)
{
  struct javacurl *curl = (struct javacurl *)stream;
  size_t realsize = size * nmemb;
  JNIEnv *java = curl->write.java;
  jbyteArray jb=NULL;
  int ret=0;

  fprintf(stderr, "%d bytes data received in callback, ptr %p, java =%p\n",
          realsize, curl, java);

  jb=(*java)->NewByteArray(java, realsize);
  (*java)->SetByteArrayRegion(java, jb, 0, 
                              realsize, (jbyte *)ptr);

  fprintf(stderr, "created byte-array\n");

  ret = (*java)->CallIntMethod(java,
                               curl->write.object,
                               curl->write.mid,
                               jb);

  fprintf(stderr, "java-method returned %d\n", ret);

  return realsize;
}

/*
 * setopt() int + object
 */

JNIEXPORT jint JNICALL Java_CurlGlue_jni_1setopt__IILCurlWrite_2
  (JNIEnv *java, jobject myself, jint jcurl, jint option, jobject object)
{
  jclass cls = (*java)->GetObjectClass(java, object);
  jmethodID mid;
  struct javacurl *curl = (struct javacurl *)jcurl;

  printf("setopt int + object, option = %d cls= %p\n", option, cls);

  switch(option) {
  case CURLOPT_WRITEFUNCTION:
    /* this is the write callback */
    mid = (*java)->GetMethodID(java, cls, "handleString",
                               "([B)I");
    if(!mid) {
      /* no callback method found */
      puts("no callback method found");
      return 0;
    }
    curl->write.mid = mid;
    curl->write.java = java;
    curl->write.object = object;

    fprintf(stderr, "setopt write callback and write file pointer %p, java = %p\n",
            curl, java);

    curl_easy_setopt(curl->libcurl, CURLOPT_WRITEFUNCTION,
                     javacurl_write_callback);
    curl_easy_setopt(curl->libcurl, CURLOPT_FILE,
                     curl);
    break;
  }
  return 0;
}

JNIEXPORT jint JNICALL Java_CurlGlue_getinfo
  (JNIEnv *java, jobject value)
{
    return 0;
}

JNIEXPORT jint JNICALL Java_CurlGlue_jni_1perform
  (JNIEnv *java, jobject myself, jint jcurl)
{
  void *handle=(void *)((struct javacurl*)jcurl)->libcurl;
  return (jint)curl_easy_perform(handle);
}
