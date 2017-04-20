/*
 * This tests different memcmp() implementations for timing differences between equal
 * and unequal input. The intention is to detect which ones could be easily attacked
 * by timing attacks.
 *
 *
 * gcc -lcrypto memcmp_bench.c
 * cd /sys/devices/system/cpu
 * echo performance | tee cpu* /cpufreq/scaling_governor
 * taskset 0x04 nice -n -20 ./a.out 16
 * 
 * Author: Eric.Sesterhenn@x41-dsec.de
 */
#include <stdio.h>
#include <sys/types.h>
#include <err.h>
#include <string.h>
#include <stddef.h>
#include <unistd.h>
#include <stdint.h>
#include <stdlib.h>
#include <openssl/crypto.h>
#include <emmintrin.h>

#define MAXCOMPARESIZE 1024

typedef unsigned long long ticks;
ticks get_ticks()
{
	ticks           ret = 0;
	unsigned long   minor = 0;
	unsigned long   mayor = 0;

	asm             volatile(
                                                 "cpuid \n"
				                 "rdtsc"
				 :               "=a"(minor),
				                 "=d"(mayor)
                                 : "a" (0)
                                 : "%ebx", "%ecx"
	);

	ret = ((((ticks) mayor) << 32) | ((ticks) minor));

	return ret;
}

// ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
// Run-of-the-mill implementation
int naiive_memcmp(const void *a1, const void *b1, size_t len) {
	unsigned int i;
	const char *a = a1;
	const char *b = b1;
	for (i=0; i<len; i++) {
		if(b[i] != a[i])
			return a-b; 
	}
	return 0;
}

// ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
// possibly optimized version of the local libc
int glibc_memcmp(const void *a, const void *b, size_t len) {
	return memcmp(a, b, len);
}

// ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
// constant time of local openssl, semantics are slightly different
int openssl_memcmp(const void *a, const void *b, size_t len) {
	return CRYPTO_memcmp(a, b, len);
}

// ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
// built in memcmp provided by gcc (calls glibc on my system)
int builtin_memcmp(const void *a, const void *b, size_t len) {
	return __builtin_memcmp(a, b, len);
}

// ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
// from https://github.com/chmike/cst_time_memcmp/blob/master/consttime_memcmp.c
int consttime_memcmp(const void *b1, const void *b2, size_t len)
{
	const uint8_t *c1, *c2;
	uint16_t d, r, m;

	volatile uint16_t v;

	c1 = b1;
	c2 = b2;

	r = 0;
	while (len) {
		v = ((uint16_t)(uint8_t)r)+255;
		m = v/256-1;

		d = (uint16_t)((int)*c1 - (int)*c2);

		r |= (d & m);

		/*
		 * Increment pointers, decrement length, and loop.
		 */
		++c1;
		++c2;
		--len;
	}

	return (/*e*/ int)(/*d*/
	    (/*c*/ int32_t)(/*b*/ uint16_t)(/*a*/ (uint32_t)r + 0x8000)
	    - 0x8000);
}

// ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
// taken from https://github.com/jgarzik/moxiebox/blob/master/runtime/memcmp.c#L88
/* Nonzero if either X or Y is not aligned on a "long" boundary.  */
#define UNALIGNED(X, Y) \
  (((long)X & (sizeof (long) - 1)) | ((long)Y & (sizeof (long) - 1)))

/* How many bytes are copied each iteration of the word copy loop.  */
#define LBLOCKSIZE (sizeof (long))

/* Threshhold for punting to the byte copier.  */
#define TOO_SMALL(LEN)  ((LEN) < LBLOCKSIZE)

int blockbased_memcmp(const void *m1, const void *m2, size_t n)
{
  unsigned char *s1 = (unsigned char *) m1;
  unsigned char *s2 = (unsigned char *) m2;
  unsigned long *a1;
  unsigned long *a2;

  /* If the size is too small, or either pointer is unaligned,
     then we punt to the byte compare loop.  Hopefully this will
     not turn up in inner loops.  */
  if (!TOO_SMALL(n) && !UNALIGNED(s1,s2))
    {
      /* Otherwise, load and compare the blocks of memory one
         word at a time.  */
      a1 = (unsigned long*) s1;
      a2 = (unsigned long*) s2;
      while (n >= LBLOCKSIZE)
        {
          if (*a1 != *a2)
   	    break;
          a1++;
          a2++;
          n -= LBLOCKSIZE;
        }

      /* check m mod LBLOCKSIZE remaining characters */

      s1 = (unsigned char*)a1;
      s2 = (unsigned char*)a2;
    }

  while (n--)
    {
      if (*s1 != *s2)
	return *s1 - *s2;
      s1++;
      s2++;
    }

  return 0;
}

// ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
// OpenBSD Userspace
// http://cvsweb.openbsd.org/cgi-bin/cvsweb/~checkout~/src/lib/libc/string/timingsafe_memcmp.c?rev=1.2&content-type=text/plain
int
timingsafe_memcmp(const void *b1, const void *b2, size_t len)
{
#ifndef CHAR_BIT
#define CHAR_BIT 8
#endif
        const unsigned char *p1 = b1, *p2 = b2;
        size_t i;
        int res = 0, done = 0;

        for (i = 0; i < len; i++) {
                /* lt is -1 if p1[i] < p2[i]; else 0. */
                int lt = (p1[i] - p2[i]) >> CHAR_BIT;

                /* gt is -1 if p1[i] > p2[i]; else 0. */
                int gt = (p2[i] - p1[i]) >> CHAR_BIT;

                /* cmp is 1 if p1[i] > p2[i]; -1 if p1[i] < p2[i]; else 0. */
                int cmp = lt - gt;

                /* set res = cmp if !done. */
                res |= cmp & ~done;

                /* set done if p1[i] != p2[i]. */
                done |= lt | gt;
        }

        return (res);
}

// ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
// Linux-Kernel
// http://linux-crypto.vger.kernel.narkive.com/eEfuKzM5/patch-crypto-memcmp-add-constant-time-memcmp
int crypto_memcmp(const void *a, const void *b, size_t size)
{
	typedef uint8_t  u8;
	const u8 *a1 = a;
	const u8 *b1 = b;
	int ret = 0;
	size_t i;

	for (i = 0; i < size; i++) {
		ret |= *a1++ ^ *b1++;
	}
	return ret;
}

// +++++yy+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
// http://www.picklingtools.com/study.pdf
// slightly different semantics
int fast_memeq(const void *src1, const void *src2, size_t len)
{
	int ii;
	/* simple  optimization  */
	if (src1 == src2 ) return 0;
	/* Convert  char  pointers  to 4 byte  integers  */
	int32_t *src1_as_int  = (int32_t *) src1;
	int32_t *src2_as_int  = (int32_t *) src2;
	int major_passes  = len >>2;
	/*  Number of passes at 4 bytes at a time  */
	int minor_passes  = len&0x3;
	/*  last  0..3  bytes  leftover  at the end */
	for (ii =0; ii <major_passes ; ii++) {
		if (* src1_as_int ++ != *src2_as_int ++)  return 1;
		/*  compare as ints  */
	}

	/* Handle  last  few bytes , but has to be as  characters  */
	char* src1_as_char  = (char *) src1_as_int ;
	char* src2_as_char  = (char *) src2_as_int ;
	switch (minor_passes) {
		case  3: if (* src1_as_char ++ != * src2_as_char ++)  return 1;
		case  2: if (* src1_as_char ++ != * src2_as_char ++)  return 1;
		case  1: if (* src1_as_char ++ != * src2_as_char ++)  return 1;
	}
	/* If we make  it here , all  compares  succeeded  */
	return 0;
}

// ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
// from https://gist.github.com/karthick18/1361842
// using sse2
static int __sse_memcmp_tail(const uint16_t *a, const uint16_t *b, int len)
{
    switch(len)
    {
    case 8:
        if(*a++ != *b++) return -1;
    case 7:
        if(*a++ != *b++) return -1;
    case 6:
        if(*a++ != *b++) return -1;
    case 5:
        if(*a++ != *b++) return -1;
    case 4:
        if(*a++ != *b++) return -1;
    case 3:
        if(*a++ != *b++) return -1;
    case 2:
        if(*a++ != *b++) return -1;
    case 1:
        if(*a != *b) return -1;
    }
    return 0;
}

static int __sse_memcmp(const void *ta, const void *tb, size_t half_words)
{
    int i = 0;
    int aligned_a = 0, aligned_b = 0;
 
    // compatibility glue ... :P
    const uint16_t *a = ta;
    const uint16_t *b = tb;
    int len = half_words / 2;
    if (half_words & 0x1)
	return 0;

    if(!len) return 0;
    if(!a && !b) return 0;
    if(!a || !b) return -1;
    if( (unsigned long) a & 1 ) return -1;
    if( (unsigned long) b & 1 ) return -1;
    aligned_a = ( (unsigned long)a & (sizeof(__m128i)-1) );
    aligned_b = ( (unsigned long)b & (sizeof(__m128i)-1) );
    if(aligned_a != aligned_b) return -1; /* both has to be unaligned on the same boundary or aligned */
    if(aligned_a)
    {
        while( len && 
               ( (unsigned long) a & ( sizeof(__m128i)-1) ) )
        {
            if(*a++ != *b++) return -1;
            --len; 
        }
    }
    if(!len) return 0;
    while( len && !(len & 7 ) )
    {
        __m128i x = _mm_load_si128( (__m128i*)&a[i]);
        __m128i y = _mm_load_si128( (__m128i*)&b[i]);
        /*
         * _mm_cmpeq_epi16 returns 0xffff for each of the 8 half words when it matches
         */
        __m128i cmp = _mm_cmpeq_epi16(x, y);
        /* 
         * _mm_movemask_epi8 creates a 16 bit mask with the MSB for each of the 16 bytes of cmp
         */
        if ( (uint16_t)_mm_movemask_epi8(cmp) != 0xffffU) return -1; 
        len -= 8;
        i += 8;
    }
    return __sse_memcmp_tail(&a[i], &b[i], len);
}


void cmploop(char *cookiegood, char *cookiebad, size_t comparesize, int (*comp)(const void *, const void *, size_t)) {
	char *cookie;
	long long totalg = 0;
	long long totalb = 0;
	long long difference;
	int count = 10000000;
	ticks a, b;
	int i;
        char eq[2] = {0x00, 0x00};

	cookie = valloc(MAXCOMPARESIZE);
	if (!cookie)
		exit(-1);
	memset(cookie, 'A', MAXCOMPARESIZE);

	/* 
         * to compare we test against equal and different memory
	 * alternating between both in order to try to let the
	 * rest of the system affect both comparisons in an
	 * equal amount
	 */
	for (i = 0; i < count; i++) {
		a = get_ticks();
		comp(cookiegood, cookie, comparesize);
		b = get_ticks();
		totalg += (b - a);

		a = get_ticks();
		comp(cookiebad, cookie, comparesize);
		b = get_ticks();
		totalb += (b - a);
	}	
	if (totalg > totalb) {
		eq[0] = 'b';
		difference = totalg - totalb;
	} else {
		eq[0] = 'g';
		difference = totalb - totalg;
	}

	printf("%012llu,%012llu,%012llu,%s\n", totalg, totalb, difference, eq);

	free(cookie);
}

void usage() {
	printf("please provide size as argument\n");
	exit(-2);
}


int main(int argc, char **argv) {
	size_t comparesize = MAXCOMPARESIZE; // the longer the bigger should the difference be
	char *cookiegood = NULL;
	char *cookiebad = NULL;
	int (*comp)(const void *, const void *, size_t);
	int i;

	if (argc != 2)
		usage();

	comparesize = atoi(argv[1]);
	if (comparesize > MAXCOMPARESIZE)
		comparesize = MAXCOMPARESIZE;

	/* for whatever it is worth get page aligned memory */
	cookiegood = valloc(MAXCOMPARESIZE);
	cookiebad = valloc(MAXCOMPARESIZE);
	if (!cookiegood || !cookiebad) {
		free(cookiegood);	// free() accepts NULL
		free(cookiebad);
		exit(-1);
	}

	memset(cookiegood, 'A', MAXCOMPARESIZE);
	memset(cookiebad, 'A', MAXCOMPARESIZE);
	cookiebad[0] = 'B';

	printf("Version   ,Equal       ,Unequal     ,Difference  ,Faster Version\n");

	/* due to the indirection, the memcmp will not be optimized away */
	for (i = 0; i < 10; i++) {
		switch(i) {
		case 0: comp = &glibc_memcmp;      printf("glibc     ,"); break;
		case 1: comp = &naiive_memcmp;     printf("naiive    ,"); break;
		case 2: comp = &blockbased_memcmp; printf("blockbased,"); break;
		case 3: comp = &builtin_memcmp;    printf("builtin   ,"); break;
		case 4: comp = &fast_memeq;        printf("fastmemeq ,"); break;
		case 5: comp = &consttime_memcmp;  printf("consttime ,"); break;
		case 6: comp = &timingsafe_memcmp; printf("timingsafe,"); break;
		case 7: comp = &crypto_memcmp;     printf("crypto    ,"); break;
		case 8: comp = &openssl_memcmp;    printf("openssl   ,"); break;
		case 9: comp = &__sse_memcmp;      printf("sse2      ,"); break;
		}
		cmploop(cookiegood, cookiebad, comparesize, comp);
	}

	free(cookiegood);
	free(cookiebad);
	exit(0);
}
