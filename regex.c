/*
   Regular Expression Enumerator (part of Lepton's Crack)

   Copyright (C) Bernardo Reino (aka Lepton) (lepton@runbox.com)
   20040901

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place - Suite 330,
   Boston, MA 02111-1307, USA.
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <ctype.h>
#include <signal.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/types.h>

#include "global.h"

extern int LoadCharSet(const char *set);
extern int LoadLenSet(const char *set);
extern int LoadRegEx(const char *regex);

unsigned long long EnumCount, PasswordCount;
int verbose, ordered;

/*
 * K_CHARSET = Vector of characters included in brute-force keyspace
 * K_CHARSET_LEN = Length of vector
 *
 * K_LENSET = Vector of password-lengths to try
 * K_LENSET_LEN = Length of vector
 */

BYTE *K_ACTIVE;
BYTE K_ASCII[BYTE_MAX], K_CHARSET[BYTE_MAX], K_SYMBOL[BYTE_MAX];
BYTE K_LENSET[MAX_PASS_LEN];
int K_CHARSET_LEN, K_LENSET_LEN;

struct regex_t *K_REGEX;
int RXMinLength, RXWildCount;

volatile int CtrlC;

#ifdef __MINGW_H
  #include <sys/timeb.h>

  void gettimeofday(struct timeval* tp, void *null) {
    struct timeb tm;
    ftime(&tm);
    tp->tv_sec  = tm.time;
    tp->tv_usec = tm.millitm * 1000;
  }
#endif

void sig_CtrlC(int q) {
  CtrlC = 1;

  /* next CTRL-C will work as usual */
  signal(SIGINT, SIG_DFL);
}

/*
 * Display a password, where ith-letter is K_CHARSET[stream[i]]
 */

void print_key(FILE *f, BYTE *stream, unsigned int len) {
  while(len --)
    fprintf(f, "%c", K_ACTIVE[(int)*(stream ++)]);
}

static void rx_enum(int len, int avail, char *prefix,
		    const struct regex_t *rx) {
  if(CtrlC) return;

  EnumCount ++;

  if(rx) {
    int j;

    if(rx->wild) {
      switch(avail) {
      case 0: /* ignore wildcard */
        rx_enum(len, avail, prefix, rx->next);
        break;

      default:
	rx_enum(len, avail, prefix, rx->next);

        for(j = 0; j < BYTE_MAX; j ++) {
          if(rx->symbol[j] > 0) {
            prefix[len] = j;
            rx_enum(len + 1, avail - 1, prefix, rx);
          }
        }
        break;
      }
    } else {
      for(j = 0; j < BYTE_MAX; j ++) {
	if(rx->symbol[j] > 0) {
	  prefix[len] = j;
	  rx_enum(len + 1, avail, prefix, rx->next);
	}
      }
    }
  } else {
    print_key(stdout, prefix, len);
    printf("\n");

    PasswordCount ++;
  }
}

static void rx_enum_ordered(int len, int avail, char *prefix,
		    const struct regex_t *rx) {
  if(CtrlC) return;

  EnumCount ++;

  if(rx) {
    int j;

    if(rx->wild) {
      if(avail) {
        for(j = 0; j < BYTE_MAX; j ++) {
          if(rx->symbol[j] > 0) {
            prefix[len] = j;
            rx_enum_ordered(len + 1, avail - 1, prefix, rx);
          }
        }
      }

      rx_enum_ordered(len, avail, prefix, rx->next);
    } else {
      for(j = 0; j < BYTE_MAX; j ++) {
	if(rx->symbol[j] > 0) {
	  prefix[len] = j;
	  rx_enum_ordered(len + 1, avail, prefix, rx->next);
	}
      }
    }
  } else { /* rx == null */
    if(len && (avail == 0)) {
      print_key(stdout, prefix, len);
      printf("\n");

      PasswordCount ++;
    }
  }
}

void RegexCrack(void) {
  char check[MAX_PASS_LEN];
  int len_idx, len;

  K_ACTIVE = K_ASCII;

  for(len = 0, len_idx = 0; len_idx < K_LENSET_LEN; len_idx ++)
    if(K_LENSET[len_idx] > len)
      len = K_LENSET[len_idx];

  if(len < RXMinLength) {
    fprintf(stderr, "(dbg) Len = %d, must be greater than %d.. OK\n",
	    len, RXMinLength);
    len = RXMinLength;
  }

  fprintf(stderr, "(dbg) rx_enum(len = %d)\n", len);

  if(ordered) {
    int x;

    for(x = 0; x <= len - RXMinLength; x ++)
      rx_enum_ordered(0, x, check, K_REGEX);
  } else
    rx_enum(0, len - RXMinLength, check, K_REGEX);
}

void BeginCrack(void) {
  struct timeval t0, t1;
  double lapse;

  signal(SIGINT, sig_CtrlC);
  gettimeofday(&t0, NULL);

  RegexCrack();

  gettimeofday(&t1, NULL);
  lapse = (t1.tv_sec - t0.tv_sec) + (t1.tv_usec - t0.tv_usec)/1000000.0;

  if(CtrlC) {
    fprintf(stderr, "\ngot Ctrl-C signal, exiting...\n");
  }

  /* verbose? */

#ifdef __MINGW_H
  fprintf(stderr,
	  "Lapse: %.5gs, Checked: %I64u, Enum: %I64u, Speed: %I64u passwd/s\n",
	  lapse, PasswordCount, EnumCount,
	  (unsigned long long)((double)PasswordCount / lapse));
#else
  fprintf(stderr,
	  "Lapse: %.5gs, Checked: %llu, Enum: %llu, Speed: %llu passwd/s\n",
	  lapse, PasswordCount, EnumCount,
	  (unsigned long long)((double)PasswordCount / lapse));
#endif

  signal(SIGINT, SIG_DFL);
}

void usage(int e, char *prog) {
  FILE *f = e ? stderr : stdout;

  fprintf(f, "usage: %s [-q | -v] "
	  "-s <charset> -g <regex> -l <lenset>\n",
	  prog);

  exit(e);
}

int main(int argc, char **argv) {
  char *default_set = "a-z0-9";
  char *default_len = "1-8";
  char *default_regex = NULL;

  int j;

  K_REGEX = NULL;

  CtrlC = 0;

  verbose = 1;
  ordered = 1;

  for(j = 1; j < argc; j ++) {
    if(!strcmp(argv[j], "-s")) {
      default_set = argv[++ j];
    }
    else if(!strcmp(argv[j], "-l")) {
      default_len = argv[++ j];
    }
    else if(!strcmp(argv[j], "-g")) {
      default_regex = argv[++ j];
    }
    else if(!strcmp(argv[j], "-g#")) {
      default_regex = argv[++ j];
      ordered = 0;
    }
    else if(!strcmp(argv[j], "-q")) {
      verbose = 0;
    }
    else if(!strcmp(argv[j], "-v")) {
      verbose = 1;
    }
    else if(!strcmp(argv[j], "-h")) {
      usage(0, argv[0]);
    }
    else {
      usage(1, argv[0]);
    }
  }

  if(LoadCharSet(default_set) == -1)
    exit(3);

  if(LoadLenSet(default_len) == -1)
    exit(4);

  if(default_regex) {
    if(LoadRegEx(default_regex) == -1)
      exit(5);
  } else
    usage(2, argv[0]);

  for(j = 0; j < sizeof(K_ASCII); j ++)
    K_ASCII[j] = j;

  BeginCrack();

  return 0;
}
