
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
    jclass cls; /* global reference */
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

  struct javacurl *curl = (struct javacurl*)jcurl;

  if(curl->write.cls) {
    /* a global reference we must delete */
    (*java)->DeleteGlobalRef(java, curl->write.cls);
    (*java)->DeleteGlobalRef(java, curl->write.object);
  }

  curl_easy_cleanup(curl->libcurl); /* cleanup libcurl stuff */

  free((void *)curl); /* free the struct too */
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
  CURLoption opt = (CURLoption)option;

  puts("setopt int + int");

  switch(opt) {
  case CURLOPT_FILE:
    /* silently ignored, we don't need user-specified callback data when
       we have an object, and besides the CURLOPT_FILE is not exported
       to the java interface */
    return 0;
  }

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

  fprintf(stderr, "%d bytes data received in callback:\n"
          "ptr=%p, java=%p cls=%p\n",
          realsize, curl, java, curl->write.cls);

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
  jclass cls_local = (*java)->GetObjectClass(java, object);
  jmethodID mid;
  struct javacurl *curl = (struct javacurl *)jcurl;
  jclass cls;
  jobject obj_global;

  switch(option) {
  case CURLOPT_WRITEFUNCTION:
    /* this makes a reference that'll be alive until we kill it! */
    cls = (*java)->NewGlobalRef(java, cls_local);

    printf("setopt int + object, option = %d cls= %p\n",
           option, cls);

    if(!cls) {
      puts("couldn't make local reference global");
      return 0;
    }

    /* this is the write callback */
    mid = (*java)->GetMethodID(java, cls, "handleString", "([B)I");
    if(!mid) {
      puts("no callback method found");
      return 0;
    }

    obj_global = (*java)->NewGlobalRef(java, object);

    curl->write.mid = mid;
    curl->write.cls = cls;
    curl->write.object = obj_global;
    /*curl->write.java = java; stored on perform */

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
  struct javacurl *curl=(struct javacurl*)jcurl;
  curl->write.java = java;
  return (jint)curl_easy_perform(curl->libcurl);
}
