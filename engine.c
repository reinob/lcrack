/*
   Cracking Engine

   Copyright (C) Bernardo Reino (aka Lepton) (lepton@runbox.com)
   20021120-20040902

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

#include "xtn_def.h"
#include "xtn_method.h"
#include "global.h"

extern char *LoadExternalSpec(const char *me, 
			      const char *file, const char *spec);
extern int LoadCharSet(const char *set);
extern int LoadLenSet(const char *set);
extern int LoadRegEx(const char *regex);

xtn_cmp_t xtn_cmp;
xtn_crypt_t xtn_crypt;

/*
 * Linked List used for storing dictionary files (just the filename)
 */

typedef struct FileList_t {
  char *data;
  struct FileList_t *next;
} FileList;

/*
 * Linked List for storing pairs login/hash (read from input file)
 */

PasswordElement PasswordList[BYTE_MAX];

/*
 * PasswordCount  = Number of passwords processed
 * PasswordTotal  = Number of passwords to crack (input file)
 * PasswordLeft   = Number of passwords not cracked
 */

unsigned long long PasswordCount; /* who knows? :) */
int PasswordTotal, PasswordLeft;

FILE *pot;
int pot_file, verbose;
int do_login, do_fast, do_smart, do_scan;
int rand_mode, stdin_mode;
int rx_ordered;

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
 * Hexa display of 'stream', size = len.
 */

void print_hex(FILE *f, BYTE *stream, unsigned int len) {
  while(len --)
    fprintf(f, "%02x", *(stream ++));
}

/*
 * Display a password, where ith-letter is K_CHARSET[stream[i]]
 */

void print_key(FILE *f, BYTE *stream, unsigned int len) {
  while(len --) {
    int ch = K_ACTIVE[(int)*(stream ++)];

    if(isprint(ch))
      fprintf(f, "%c", ch);
    else
      fprintf(f, "\\x%02x", ch);
  }
}

void LoginCrack(void) {
  PasswordElement *pwd;
  char *line;
  time_t t0, t1;
  int mod_index;

  K_ACTIVE = K_ASCII;

  t0 = 0;

  for(mod_index = 0; mod_index < BYTE_MAX; mod_index ++) {
    if(CtrlC || (PasswordLeft == 0))
      break;

    for(pwd = PasswordList[mod_index].next; pwd; pwd = pwd->next) {
      if(CtrlC || (PasswordLeft == 0))
	break;

      line = pwd->login;

      if(strlen(line) >= MAX_PASS_LEN)
	continue;

      if(verbose && ((t1 = time(NULL)) > t0)) {
	fprintf(stderr,
		"                                            \r"
		"KEY: %s\r",
		line);
	fflush(stderr);
	t0 = t1;
      }

      KEY_login(line, strlen(line), 1);
    }
  }
}

void TableCrack(FileList *tbl) {
  struct elem {
    char word[16];
    BYTE hash[16];
  } next;

  time_t t0, t1;
  FileList *dptr;

  K_ACTIVE = K_ASCII;

  t0 = 0;
  dptr = tbl->next;

  for(dptr = tbl->next;
      (! CtrlC) && PasswordLeft && (dptr) && (dptr->data);
      dptr = dptr->next) {

    FILE *fp = fopen(dptr->data, "rb");

    if(fp == NULL) {
      perror(dptr->data);
      continue;
    }

    while((! CtrlC) && PasswordLeft && fread(&next, sizeof(next), 1, fp)) {
      if(verbose && ((t1 = time(NULL)) > t0)) {
	fprintf(stderr,
		"                                            \r"
		"KEY: %s\r",
		next.word);
	fflush(stderr);
	t0 = t1;
      }

      KEY_find(next.word, strlen(next.word), next.hash);
    }

    fclose(fp);
  }
}

void DictionaryCrack(FileList *dict, int round) {
  char line[128];
  time_t t0, t1;
  FileList *dptr;

  K_ACTIVE = K_ASCII;

  t0 = 0;
  dptr = dict->next;

  for(dptr = dict->next;
      (! CtrlC) && PasswordLeft && (dptr) && (dptr->data);
      dptr = dptr->next) {

    FILE *fp = fopen(dptr->data, "rt");

    if(fp == NULL) {
      perror(dptr->data);
      continue;
    }

    while((! CtrlC) && PasswordLeft && fgets(line, 128, fp)) {
      char *ptr;

      if((ptr = strrchr(line, '\n')) != NULL) *ptr = '\0';
      if((ptr = strrchr(line, '\r')) != NULL) *ptr = '\0';

      if(strlen(line) >= MAX_PASS_LEN)
	continue;

      if(verbose && ((t1 = time(NULL)) > t0)) {
	fprintf(stderr,
		"                                            \r"
		"KEY: %s\r",
		line);
	fflush(stderr);
	t0 = t1;
      }

      KEY_word(line, strlen(line), round);
    }

    fclose(fp);
  }
}

void stdinCrack(void) {
  char line[128];
  time_t t0, t1;
  int tty;

  K_ACTIVE = K_ASCII;

  t0 = 0;
  tty = isatty(0);

  while((! CtrlC) && PasswordLeft && fgets(line, 128, stdin)) {
    char *ptr;

    if((ptr = strrchr(line, '\n')) != NULL) *ptr = '\0';
    if((ptr = strrchr(line, '\r')) != NULL) *ptr = '\0';

    if(strlen(line) >= MAX_PASS_LEN)
      continue;

    if(verbose && !tty && ((t1 = time(NULL)) > t0)) {
      fprintf(stderr,
	      "                                            \r"
	      "KEY: %s\r",
	      line);
      fflush(stderr);
      t0 = t1;
    }

    KEY_word(line, strlen(line), 0);
  }
}

static void rx_enum(int len, int avail, char *prefix,
		    const struct regex_t *rx, time_t *t0) {
  if(CtrlC || (PasswordLeft == 0)) return;

  if(rx) {
    int j;

    if(rx->wild) {
      switch(avail) {
      case 0: /* ignore wildcard */
        rx_enum(len, avail, prefix, rx->next, t0);
        break;

      default:
	rx_enum(len, avail, prefix, rx->next, t0);

        for(j = 0; j < BYTE_MAX; j ++) {
          if(rx->symbol[j] > 0) {
            prefix[len] = j;
            rx_enum(len + 1, avail - 1, prefix, rx, t0);
          }
        }
        break;
      }
    } else {
      for(j = 0; j < BYTE_MAX; j ++) {
	if(rx->symbol[j] > 0) {
	  prefix[len] = j;
	  rx_enum(len + 1, avail, prefix, rx->next, t0);
	}
      }
    }
  } else {
    time_t t1;

    if(verbose && ((t1 = time(NULL)) > *t0)) {
      fprintf(stderr, "KEY: ");
      print_key(stderr, prefix, len);
      fprintf(stderr, "\r");
      fflush(stderr);
      *t0 = t1;
    }

    KEY_cmp(prefix, len);
  }
}

static void rx_enum_ordered(int len, int avail, char *prefix,
		    const struct regex_t *rx, time_t *t0) {
  if(CtrlC || (PasswordLeft == 0)) return;

  if(rx) {
    int j;

    if(rx->wild) {
      if(avail) {
        for(j = 0; j < BYTE_MAX; j ++) {
          if(rx->symbol[j] > 0) {
            prefix[len] = j;
            rx_enum_ordered(len + 1, avail - 1, prefix, rx, t0);
          }
        }
      }

      rx_enum_ordered(len, avail, prefix, rx->next, t0);
    } else {
      for(j = 0; j < BYTE_MAX; j ++) {
	if(rx->symbol[j] > 0) {
	  prefix[len] = j;
	  rx_enum_ordered(len + 1, avail, prefix, rx->next, t0);
	}
      }
    }
  } else if(len && (avail == 0)) {
    time_t t1;

    if(verbose && ((t1 = time(NULL)) > *t0)) {
      fprintf(stderr, "KEY: ");
      print_key(stderr, prefix, len);
      fprintf(stderr, "\r");
      fflush(stderr);
      *t0 = t1;
    }

    KEY_cmp(prefix, len);
  }
}

void RegexCrack(void) {
  char check[MAX_PASS_LEN];
  time_t t0;
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
  t0 = time(NULL);

  if(rx_ordered) {
    int x;

    for(x = 0; x <= len - RXMinLength; x ++)
      rx_enum_ordered(0, x, check, K_REGEX, &t0);
  } else
    rx_enum(0, len - RXMinLength, check, K_REGEX, &t0);
}

void PasswordCrack(void) {
  BYTE check[MAX_PASS_LEN];
  unsigned long long len_max;
  int len_idx, len;
  time_t t0, t1;

  K_ACTIVE = K_CHARSET;
  t0 = 0;

  for(len_idx = 0; (! CtrlC) && PasswordLeft
	&& (len_idx < K_LENSET_LEN); len_idx ++) {

    len = K_LENSET[len_idx];

    {
      unsigned int j;

      for(len_max = 1, j = 0; j < len; j ++)
	len_max *= K_CHARSET_LEN;
    }

    if(verbose)
#ifdef __MINGW_H
      fprintf(stderr, "Length = %d, Total = %I64u\n",
#else
      fprintf(stderr, "Length = %d, Total = %llu\n",
#endif
	      len, len_max);

    KEY_zero(check, len);

    while((! CtrlC) && PasswordLeft) {
      if(verbose && ((t1 = time(NULL)) > t0)) {
	fprintf(stderr, "KEY: ");
	print_key(stderr, check, len);

#ifdef __MINGW_H
	fprintf(stderr, ", R = %I64u\r", len_max);
#else
	fprintf(stderr, ", R = %llu\r", len_max);
#endif

	fprintf(stderr, "\r");
	fflush(stderr);
	t0 = t1;
      }

      KEY_cmp((char *)check, len);
      len_max --;

      if(KEY_next(check, len) < 0)
	break;
    }
  }
}

void RandomCrack(void) {
  BYTE check[MAX_PASS_LEN];
  unsigned long long len_max;
  int len_idx, len;
  time_t t0, t1;

  K_ACTIVE = K_CHARSET;
  t0 = 0;

  for(len_idx = 0; (! CtrlC) && PasswordLeft
	&& (len_idx < K_LENSET_LEN); len_idx ++) {
    len = K_LENSET[len_idx];

    {
      unsigned int j;

      for(len_max = 1, j = 0; j < len; j ++)
	len_max *= K_CHARSET_LEN;
    }

    if(verbose)
#ifdef __MINGW_H
      fprintf(stderr, "Length = %d, Total = %I64u\n",
#else
      fprintf(stderr, "Length = %d, Total = %llu\n",
#endif
	      len, len_max);

    while((! CtrlC) && PasswordLeft && len_max) {
      KEY_rand(check, len);

      if(verbose && ((t1 = time(NULL)) > t0)) {
	fprintf(stderr, "KEY: ");
	print_key(stderr, check, len);

#ifdef __MINGW_H
	fprintf(stderr, ", R = %I64u\r", len_max);
#else
	fprintf(stderr, ", R = %llu\r", len_max);
#endif

	fflush(stderr);
	t0 = t1;
      }

      KEY_cmp((char *)check, len);
      len_max --;
    }
  }
}

signed int hex(char x) {
  if((x >= '0') && (x <= '9'))
    return (x - '0');
  else if((x >= 'A') && (x <= 'F'))
    return (x - 'A' + 10);
  else if((x >= 'a') && (x <= 'f'))
    return (x - 'a' + 10);

  return -1;
}

void LoadInput(FileList *pwd_file) {
  PasswordElement *ptrLinked[BYTE_MAX];
  char line[1024];
  int mod_index;

  for(mod_index = 0; mod_index < BYTE_MAX; mod_index ++)
    ptrLinked[mod_index] = &PasswordList[mod_index];

  PasswordTotal = 0;

  while(pwd_file->next) {
    FILE *fp;

    pwd_file = pwd_file->next;
    fprintf(stderr, "dbg: loading '%s'\n", pwd_file->data);

    fp = fopen(pwd_file->data, "rt");

    if(fp) {
      while(fgets(line, 1024, fp)) {
	int i, j, pwlen, len;
	char *user, *passwd, *ptr;
	BYTE hash8[MAX_CODE_LEN];

	for(ptr = line; *ptr && isspace(*ptr); ptr ++) ;
	for(user = ptr ++; *ptr && *ptr != ':'; ptr ++) ;
	*(ptr ++) = '\0';

	for(passwd = ptr; *ptr && isxdigit(*ptr); ptr ++) ;
	*(ptr ++) = '\0';

	pwlen = strlen(passwd);

	for(len = 0, i = 0; i < pwlen; i += 2, len ++) {
	  if((j = hex(passwd[i])) < 0) goto _format;
	  hash8[len] = ((j & 0xf) << 4);

	  if((j = hex(passwd[i+1])) < 0) goto _format;
	  hash8[len] += (j & 0x0f);
	}

	goto _next;

      _format:
	fprintf(stderr, "%s: bad hexadecimal character\n", passwd);
	continue;

      _next:
	mod_index = hash8[0] & 0xff;

	ptrLinked[mod_index]->next = calloc(1, sizeof(PasswordElement));
	ptrLinked[mod_index] = ptrLinked[mod_index]->next;

	ptrLinked[mod_index]->login = strdup(user);
	memcpy(ptrLinked[mod_index]->data, hash8, len);
	ptrLinked[mod_index]->next = NULL;

	PasswordTotal ++;
      }

      fclose(fp);
    } else
      perror(pwd_file->data);
  }
}

void BeginCrack(FileList *tbl, FileList *dict) {
  struct timeval t0, t1;
  double lapse;

  signal(SIGINT, sig_CtrlC);
  PasswordLeft = PasswordTotal;

  gettimeofday(&t0, NULL);

  if(!CtrlC && PasswordLeft) {
    if(verbose)
      fprintf(stderr,
	      "mode: null password, loaded %d password%s\n",
	      PasswordLeft, PasswordLeft > 1 ? "s" : "");

    KEY_cmp("", 0);
  }

  if(do_login && !CtrlC && PasswordLeft) {
    if(verbose)
      fprintf(stderr,
	      "mode: login single crack, loaded %d password%s\n",
	      PasswordLeft, PasswordLeft > 1 ? "s" : "");

    LoginCrack();
  }

  if(stdin_mode) {
    if(verbose)
      fprintf(stderr,
	      "mode: stdin search, loaded %d password%s\n",
	      PasswordLeft, PasswordLeft > 1 ? "s" : "");

    stdinCrack();
  }

  if(do_fast && !CtrlC && PasswordLeft && tbl->next) {
    if(verbose)
      fprintf(stderr,
	      "mode: fast pre-computed table, loaded %d password%s\n",
	      PasswordLeft, PasswordLeft > 1 ? "s" : "");

    TableCrack(tbl);
  }

  if(do_fast && !CtrlC && PasswordLeft && dict->next) {
    if(verbose)
      fprintf(stderr,
	      "mode: fast dictionary search, loaded %d password%s\n",
	      PasswordLeft, PasswordLeft > 1 ? "s" : "");

    DictionaryCrack(dict, 0);
  }

  if(do_smart && !CtrlC && PasswordLeft && dict->next) {
    if(verbose)
      fprintf(stderr,
	      "mode: smart dictionary search, loaded %d password%s\n",
	      PasswordLeft, PasswordLeft > 1 ? "s" : "");

    DictionaryCrack(dict, 1);
  }

  if(do_scan && !CtrlC && PasswordLeft) {
    if(verbose)
      fprintf(stderr,
	      "mode: incremental%s, loaded %d password%s\n",
	      K_REGEX ? (rx_ordered ? " (regex, ordered)" : " (regex)") :
	      rand_mode ? " (random)" : "",
	      PasswordLeft, PasswordLeft > 1 ? "s" : "");

    if(K_REGEX)
      RegexCrack();
    else if(rand_mode)
      RandomCrack();
    else
      PasswordCrack();
  }

  gettimeofday(&t1, NULL);
  lapse = (t1.tv_sec - t0.tv_sec) + (t1.tv_usec - t0.tv_usec)/1000000.0;

  if(CtrlC) {
    fprintf(stderr, "\ngot Ctrl-C signal, exiting...\n");
  }

  /* verbose? */

  #ifdef __MINGW_H
    fprintf(stderr,
	  "Lapse: %.5gs, Checked: %I64u, Found: %d/%d, Speed: %I64u passwd/s\n",
	  lapse, PasswordCount, PasswordTotal - PasswordLeft, PasswordTotal,
	  (unsigned long long)((double)PasswordCount / lapse));
  #else
    fprintf(stderr,
	  "Lapse: %.5gs, Checked: %llu, Found: %d/%d, Speed: %llu passwd/s\n",
	  lapse, PasswordCount, PasswordTotal - PasswordLeft, PasswordTotal,
	  (unsigned long long)((double)PasswordCount / lapse));
  #endif

  signal(SIGINT, SIG_DFL);
}

void banner(void) {
  fprintf(stderr, "-= [ Lepton's Crack ] =- Password Cracker [%s]\n", __DATE__);
  fprintf(stderr, "(C)  Bernardo Reino (aka Lepton) <lepton@runbox.com>\n");
  fprintf(stderr, " and Miguel Dilaj (aka Nekromancer) <nekromancer@eudoramail.com>\n");
  fprintf(stderr, "\n");
}

void usage(int e, char *prog) {
  FILE *f = e ? stderr : stdout;
  struct xtn_module_t *xtn_ptr;

  fprintf(f, "usage: %s [-q | -v] -m <method> [<opts>] <file> ..\n",
	  prog);

  fprintf(f, " -o  <file>     : output password file\n");
  fprintf(f, " -d  <file>     : use word list from <file>\n");
  fprintf(f, " -t  <file>     : use pre-computed word list from <file>\n");
  fprintf(f, " -s  <charset>  : use specified charset for incremental\n");
  fprintf(f, " -s# <name>     : use charset from charset.txt file\n");
  fprintf(f, " -l  <lenset>   : use specified length-set for incremental\n");
  fprintf(f, " -g  <regex>    : enumerate regex for incremental\n");
  fprintf(f, " -g# <name>     : use regex from regex.txt file\n");
  fprintf(f, " -x<mode>[+|-]  : activate/deactivate specified mode\n");
  fprintf(f, "   mode = l     : login mode\n");
  fprintf(f, "   mode = f     : fast word list mode\n");
  fprintf(f, "   mode = s     : smart word list mode\n");
  fprintf(f, "   mode = b     : incremental (brute-force) mode\n");
  fprintf(f, " -stdin         : stdin (external) mode\n");
  fprintf(f, " -rand          : randomized brute-force mode\n");
  fprintf(f, " -h             : display usage information and exit\n");
  fprintf(f, " <method>       : hash algorithm, one of:\n");
  fprintf(f, "                { ");

  for(xtn_ptr = &xtn_all[0]; xtn_ptr->xtn_text; xtn_ptr ++) {
    fprintf(f, "'%s' ", xtn_ptr->xtn_text);
  }

  fprintf(f, "}\n");
  exit(e);
}

int main(int argc, char **argv) {
  char * default_cipher = NULL;
  char * default_set = "a-z0-9";
  char * default_len = "1-8";
  char * default_regex = NULL;

  char * external_set = NULL;
  char * external_regex = NULL;

  FileList *tbl_file, *tbl_ptr;
  FileList *dict_file, *dict_ptr;
  FileList *pwd_file, *pwd_ptr;

  struct xtn_module_t *xtn_ptr;

  int j, files = 0;

  banner();
  srand((unsigned int)time(NULL));

  tbl_ptr = tbl_file = calloc(1, sizeof(FileList));
  dict_ptr = dict_file = calloc(1, sizeof(FileList));
  pwd_ptr = pwd_file = calloc(1, sizeof(FileList));

  K_REGEX = NULL;

  CtrlC = 0;

  pot = stdout;
  pot_file = 0;
  verbose = 1;
  xtn_crypt = NULL;
  xtn_cmp = NULL;

  do_login = 0;
  do_fast = 0;
  do_smart = 0;
  do_scan = 0;

  stdin_mode = 0;
  rx_ordered = 1;

  for(j = 1; j < argc; j ++) {
    if(!strcmp(argv[j], "-m")) {
      default_cipher = argv[++ j];
    }
    else if(!strcmp(argv[j], "-stdin")) {
      stdin_mode = 1;
    }
    else if(!strcmp(argv[j], "-d")) {
      dict_ptr->next = calloc(1, sizeof(*dict_ptr));
      dict_ptr = dict_ptr->next;

      dict_ptr->data = strdup(argv[++ j]);
      dict_ptr->next = NULL;
    }
    else if(!strcmp(argv[j], "-t")) {
      tbl_ptr->next = calloc(1, sizeof(*tbl_ptr));
      tbl_ptr = tbl_ptr->next;

      tbl_ptr->data = strdup(argv[++ j]);
      tbl_ptr->next = NULL;
    }
    else if(!strcmp(argv[j], "-s")) {
      default_set = argv[++ j];
    }
    else if(!strcmp(argv[j], "-s#")) {
      external_set = LoadExternalSpec(argv[0], "charset.txt", argv[++ j]);

      if(external_set) {
	default_set = external_set;
      }
    }
    else if(!strcmp(argv[j], "-l")) {
      default_len = argv[++ j];
    }
    else if(!strcmp(argv[j], "-g")) {
      default_regex = argv[++ j];
      rx_ordered = 1;
    }
    else if(!strcmp(argv[j], "-g#")) {
      external_regex = LoadExternalSpec(argv[0], "regex.txt", argv[++ j]);

      if(external_regex) {
	default_regex = external_regex;
	rx_ordered = 1;
      }
    }
    else if(!strcmp(argv[j], "-q")) {
      verbose = 0;
    }
    else if(!strcmp(argv[j], "-v")) {
      verbose = 1;
    }
    else if(!strcmp(argv[j], "-o")) {
      pot = fopen(argv[++ j], "at");
      if(pot == NULL) {
	perror(argv[j]);
	exit(2);
      } else
	pot_file = 1;
    }
    else if(!strcmp(argv[j], "-h")) {
      usage(0, argv[0]);
    }
    else if(!strcmp(argv[j], "-rand")) {
      rand_mode = 1;
    }
    else if(!strncmp(argv[j], "-x", 2) && (strlen(argv[j]) > 3)) {
      int what = argv[j][2];
      int mode = argv[j][3];

      switch(mode) {
      case '+': mode = 1; break;
      case '-': mode = 0; break;
      default:
	usage(1, argv[0]);
      }

      switch(what) {
      case 'l': do_login = mode; break;
      case 'f': do_fast = mode; break;
      case 's': do_smart = mode; break;
      case 'b': do_scan = mode; break;
      default:
	usage(1, argv[0]);
      }
    }
    else if(argv[j][0] == '-') {
      usage(1, argv[0]);
    }
    else {
      pwd_ptr->next = calloc(1, sizeof(*pwd_ptr));
      pwd_ptr = pwd_ptr->next;

      pwd_ptr->data = strdup(argv[j]);
      pwd_ptr->next = NULL;

      files ++;
    }
  }

  if((default_cipher == NULL) || (default_cipher[0] == '\0')) {
    fprintf(stderr, "%s: method must be specified (-m), exiting..\n",
	    argv[0]);
    usage(1, argv[0]);
  }

  for(xtn_ptr = &xtn_all[0]; xtn_ptr->xtn_text; xtn_ptr ++) {
    if(!strcmp(default_cipher, xtn_ptr->xtn_text)) {
      xtn_ptr->xtn_init();
      xtn_cmp = xtn_ptr->xtn_check;
      xtn_crypt = xtn_ptr->xtn_function;
    }
  }

  if(xtn_crypt == NULL) {
    fprintf(stderr, "%s: method '%s' not implemented, exiting..\n",
	    argv[0], default_cipher);
    usage(3, argv[0]);
  }

  if(rand_mode && !do_scan) {
    fprintf(stderr,
	    "%s: random mode set, but incremental not used, ignoring..\n",
	    argv[0]);
  }

  if(LoadCharSet(default_set) == -1)
    exit(4);

  if(LoadLenSet(default_len) == -1)
    exit(5);

  if(default_regex) {
    if(LoadRegEx(default_regex) == -1)
      exit(6);
  }

  for(j = 0; j < sizeof(K_ASCII); j ++)
    K_ASCII[j] = j;

  if(files == 0) {
    fprintf(stderr, "%s: need at least one input file!\n",
	    argv[0]);
    usage(1, argv[0]);
  }

  LoadInput(pwd_file);
  BeginCrack(tbl_file, dict_file);

  if(pot_file && pot)
    fclose(pot);

  if(external_set)
    free(external_set);

  if(external_regex)
    free(external_regex);

  return 0;
}
