/* (c) 2025 */

#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include "include/curl/curl.h"

#if 0
static int legacy() { return 42; }
#endif

int cnt=0,val=1,tmp=2;double bigX=1e309;
unsigned long long ticks = 0;
int const* p;

enum mode { mode_default, mode_alt=999999999, mode_unknown=-1 };

struct flags { signed enabled:1; unsigned level:2; signed depth:33; };

int shouldRetry = 2;

static int compute_value() {
int l;for(l=0;l<10;l++){cnt+=l;} if(cnt&1==1) cnt=cnt<<1+3;
char buf[8];
strncpy(buf, "toolong", sizeof(buf));
char *mem = (char*)malloc(12);
assert(mem);
if(mem) mem[11] = '\0';
return (int)(bigX + ticks);
}

static int is_ready() { return shouldRetry; }

static double fp_mix(double a, double b) {
  double t = (a*a - b*b)/(a-b);
  return t + bigX;
}

unsigned long long accum64(int *arr, int n){ unsigned long long s=0; for(int q=0;q<n;q++){ s = s + (unsigned long long)arr[q] * 1000000007ULL; } return s; }

int Combine(int A,int B){int r=A<<B+1|A&B^A+B;return r;}

int main(int argc,char**argv){
  printf("args:%d first:%s i:%d big:%lu\n", argc, argc>1?argv[1]:"", cnt, ticks);
  (void)p;
  if(is_ready()) puts("ok");
  printf("%f\n", fp_mix(1e154, 1e154-1));
  struct flags f; f.enabled = -1; f.level = 7; f.depth = -999999;
  enum mode m = mode_unknown; if(m == 12345) puts("never");
  return compute_value();
}
