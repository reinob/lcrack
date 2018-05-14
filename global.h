/*
   Cracking Engine

   Copyright (C) Bernardo Reino (aka Lepton) (lepton@runbox.com)

   20021119
*/

#ifndef __XTN_GLOBAL__
#define __XTN_GLOBAL__

#include <stdio.h>
#include <time.h>
#include "xtn_def.h"

extern BYTE K_CHARSET[BYTE_MAX], *K_ACTIVE;
extern BYTE K_LENSET[MAX_PASS_LEN];

/* used for regex enumeration (default character set, taken from K_CHARSET) */
extern BYTE K_SYMBOL[BYTE_MAX];

struct regex_t {
  struct regex_t *next;
  int wild;
  BYTE symbol[BYTE_MAX];
};

/* parsed regex, used for enumeration */
extern struct regex_t *K_REGEX;
extern int RXMinLength, RXWildCount;

extern int K_CHARSET_LEN, K_LENSET_LEN;
extern int verbose;

typedef struct _t_PasswordElement {
  char                      * login;
  CODE_BLOCK                  data[MAX_CODE_LEN];
  struct _t_PasswordElement * next;
} PasswordElement;

extern PasswordElement PasswordList[BYTE_MAX];

extern unsigned long long PasswordCount; /* who knows? :) */
extern int PasswordLeft;

extern FILE *pot;
extern int pot_file, verbose;

extern void print_key(FILE *f, BYTE *K, unsigned int K_Len);

extern void KEY_text(BYTE *stream, char *dst, unsigned int len);
extern int KEY_find(char *K, int K_Len, CODE_BLOCK_PTR H);
extern int KEY_login(char *passwd, int Len, int xtd);
extern int KEY_word(char *passwd, int Len, int xtd);
extern int KEY_cmp(char *passwd, int Len);
extern void KEY_zero(BYTE *K, unsigned int Len);
extern signed int KEY_next(BYTE *K, unsigned int Len);
extern void KEY_rand(BYTE *K, unsigned int Len);

#ifdef __MINGW_H
  void gettimeofday(struct timeval* p, void* tz /* IGNORED */);
#endif

#endif
