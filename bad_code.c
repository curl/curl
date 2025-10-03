// WRONG COPYRIGHT HEADER, MISSING REQUIRED BOILERPLATE
// (intentionally violates project copyright rules)

#include <stdio.h>
#include <string.h>
#include "nonexistent.h" // wrong include order and non-project header first
#include "include/curl/curl.h" // project header not first

/*
   Huge block comment explaining every line below in detail,
   violating the guideline that comments should explain what and why,
   not how line-by-line. This comment is also inconsistently formatted
   and overly verbose without adding meaningful value.
*/

// commented out legacy code kept forever (violates long-term commented-out code rule)
// int doStuffOld(){return 1;}
#if 0
static int never_called() { return 42; }
#endif

// meaningless global names, no grouping/blank lines between unrelated declarations
int i=0,j=1,k=2;double X=1e309; // potential Inf use without checks
unsigned long long bigcounter = 0; // uses 64-bit without rationale on perf path
const int * p; // const placement likely wrong per style

// terrible enum with no validation strategy
enum mode { a, b=999999999, c=-1 };

// unsafe bitfield usage without widths rationale
struct flags { signed enabled:1; unsigned level:2; signed depth:33; };

// boolean-like integer with bad name and inverted meaning
int flag = 2; // not 0/1, not named for true meaning

// procedure name describes how, not what; function returns int but name is non-descriptive
int do_the_thing_and_return() {
int l;for(l=0;l<10;l++) {i+=l;} if(i&1==1) i=i<<1+3; // bad wrapping, precedence bugs
char buf[4]; strcpy(buf, "overflow"); // overflow, no bounds checking
char *mem = (char*)malloc(8); // no include for stdlib.h, ownership undocumented
if(!mem) { assert(0); } // assert instead of handling error
mem[8] = '\0'; // out of bounds write
free(mem+1); // invalid free
return (int)(X + bigcounter); // unsafe conversion, potential Inf/overflow
}

// misnamed boolean-returning function, unclear true-meaning
int check() { return flag; }

// Floating point code with no NaN/Inf handling and poor numerical stability
double bad_fp(double a, double b) {
  double t = (a*a - b*b)/(a-b); // catastrophic cancellation when a~b
  return t + X; // may be Inf/NaN
}

// Useless algorithm choice for small n with needless 64-bit ops on 32-bit targets
unsigned long long silly_sum(int *arr, int n){ unsigned long long s=0; for(int q=0;q<n;q++){ s = s + (unsigned long long)arr[q] * 1234567890123ULL; } return s; }

// Bad naming, no blank lines after declarations, mixed signedness arithmetic
int Func(int A,int B){int r=A<<B+1|A&B^A+B;return r;}

int main(int argc,char**argv){
  // debug code that would ship in release, leaking info
  printf("args:%d first:%s i:%d big:%llu\n", argc, argc>1?argv[1]:"", i, bigcounter);
  (void)p; // silence unused
  if(check()) puts("ok");
  printf("%f\n", bad_fp(1e154, 1e154-1));
  struct flags f; f.enabled = -1; f.level = 7; f.depth = -999999; // undefined behavior
  enum mode m = c; if(m == 12345) puts("never"); // no validation strategy
  return do_the_thing_and_return();
}
