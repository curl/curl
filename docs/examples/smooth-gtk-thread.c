/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2019, Daniel Stenberg, <daniel@haxx.se>, et al.
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
 ***************************************************************************/
/* <DESC>
 * A multi threaded application that uses a progress bar to show
 * status.  It uses Gtk+ to make a smooth pulse.
 * </DESC>
 */
/*
 * Written by Jud Bishop after studying the other examples provided with
 * libcurl.
 *
 * To compile (on a single line):
 * gcc -ggdb `pkg-config --cflags  --libs gtk+-2.0` -lcurl -lssl -lcrypto
 *   -lgthread-2.0 -dl  smooth-gtk-thread.c -o smooth-gtk-thread
 */

#include <stdio.h>
#include <gtk/gtk.h>
#include <glib.h>
#include <unistd.h>
#include <pthread.h>

#include <curl/curl.h>

#define NUMT 4

pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
int j = 0;
gint num_urls = 9; /* Just make sure this is less than urls[]*/
const char * const urls[]= {
  "90022",
  "90023",
  "90024",
  "90025",
  "90026",
  "90027",
  "90028",
  "90029",
  "90030"
};

size_t write_file(void *ptr, size_t size, size_t nmemb, FILE *stream)
{
  /* printf("write_file\n"); */
  return fwrite(ptr, size, nmemb, stream);
}

/* https://weather.com/weather/today/l/46214?cc=*&dayf=5&unit=i */
void *pull_one_url(void *NaN)
{
  /* Stop threads from entering unless j is incremented */
  pthread_mutex_lock(&lock);
  while(j < num_urls) {
    CURL *curl;
    gchar *http;

    printf("j = %d\n", j);

    http =
      g_strdup_printf("xoap.weather.com/weather/local/%s?cc=*&dayf=5&unit=i\n",
                      urls[j]);

    printf("http %s", http);

    curl = curl_easy_init();
    if(curl) {

      FILE *outfile = fopen(urls[j], "wb");

      /* Set the URL and transfer type */
      curl_easy_setopt(curl, CURLOPT_URL, http);

      /* Write to the file */
      curl_easy_setopt(curl, CURLOPT_WRITEDATA, outfile);
      curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_file);

      j++;  /* critical line */
      pthread_mutex_unlock(&lock);

      curl_easy_perform(curl);

      fclose(outfile);
      printf("fclose\n");

      curl_easy_cleanup(curl);
    }
    g_free(http);

    /* Adds more latency, testing the mutex.*/
    sleep(1);

  } /* end while */
  return NULL;
}


gboolean pulse_bar(gpointer data)
{
  gdk_threads_enter();
  gtk_progress_bar_pulse(GTK_PROGRESS_BAR (data));
  gdk_threads_leave();

  /* Return true so the function will be called again;
   * returning false removes this timeout function.
   */
  return TRUE;
}

void *create_thread(void *progress_bar)
{
  pthread_t tid[NUMT];
  int i;

  /* Make sure I don't create more threads than urls. */
  for(i = 0; i < NUMT && i < num_urls ; i++) {
    int error = pthread_create(&tid[i],
                               NULL, /* default attributes please */
                               pull_one_url,
                               NULL);
    if(0 != error)
      fprintf(stderr, "Couldn't run thread number %d, errno %d\n", i, error);
    else
      fprintf(stderr, "Thread %d, gets %s\n", i, urls[i]);
  }

  /* Wait for all threads to terminate. */
  for(i = 0; i < NUMT && i < num_urls; i++) {
    pthread_join(tid[i], NULL);
    fprintf(stderr, "Thread %d terminated\n", i);
  }

  /* This stops the pulsing if you have it turned on in the progress bar
     section */
  g_source_remove(GPOINTER_TO_INT(g_object_get_data(G_OBJECT(progress_bar),
                                                    "pulse_id")));

  /* This destroys the progress bar */
  gtk_widget_destroy(progress_bar);

  /* [Un]Comment this out to kill the program rather than pushing close. */
  /* gtk_main_quit(); */


  return NULL;

}

static gboolean cb_delete(GtkWidget *window, gpointer data)
{
  gtk_main_quit();
  return FALSE;
}

int main(int argc, char **argv)
{
  GtkWidget *top_window, *outside_frame, *inside_frame, *progress_bar;

  /* Must initialize libcurl before any threads are started */
  curl_global_init(CURL_GLOBAL_ALL);

  /* Init thread */
  g_thread_init(NULL);
  gdk_threads_init();
  gdk_threads_enter();

  gtk_init(&argc, &argv);

  /* Base window */
  top_window = gtk_window_new(GTK_WINDOW_TOPLEVEL);

  /* Frame */
  outside_frame = gtk_frame_new(NULL);
  gtk_frame_set_shadow_type(GTK_FRAME(outside_frame), GTK_SHADOW_OUT);
  gtk_container_add(GTK_CONTAINER(top_window), outside_frame);

  /* Frame */
  inside_frame = gtk_frame_new(NULL);
  gtk_frame_set_shadow_type(GTK_FRAME(inside_frame), GTK_SHADOW_IN);
  gtk_container_set_border_width(GTK_CONTAINER(inside_frame), 5);
  gtk_container_add(GTK_CONTAINER(outside_frame), inside_frame);

  /* Progress bar */
  progress_bar = gtk_progress_bar_new();
  gtk_progress_bar_pulse(GTK_PROGRESS_BAR (progress_bar));
  /* Make uniform pulsing */
  gint pulse_ref = g_timeout_add(300, pulse_bar, progress_bar);
  g_object_set_data(G_OBJECT(progress_bar), "pulse_id",
                    GINT_TO_POINTER(pulse_ref));
  gtk_container_add(GTK_CONTAINER(inside_frame), progress_bar);

  gtk_widget_show_all(top_window);
  printf("gtk_widget_show_all\n");

  g_signal_connect(G_OBJECT (top_window), "delete-event",
                   G_CALLBACK(cb_delete), NULL);

  if(!g_thread_create(&create_thread, progress_bar, FALSE, NULL) != 0)
    g_warning("can't create the thread");

  gtk_main();
  gdk_threads_leave();
  printf("gdk_threads_leave\n");

  return 0;
}
