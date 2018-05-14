/* 
   Cracking Engine

   Copyright (C) Bernardo Reino (aka Lepton) (lepton@runbox.com)

   20021119
*/

#ifndef __XTN_DEF__
#define __XTN_DEF__

/*
 * Maximum size for a hash/encrypted password
 */

#include <limits.h>

#define MAX_CODE_LEN 64
#define MAX_PASS_LEN 16

typedef unsigned char BYTE;

#define BYTE_MAX (2 << CHAR_BIT)

typedef BYTE* CODE_BLOCK_PTR;
typedef BYTE  CODE_BLOCK;

typedef CODE_BLOCK_PTR (*xtn_crypt_t)(char *, int, BYTE *);
typedef int (*xtn_cmp_t)(CODE_BLOCK_PTR, CODE_BLOCK_PTR);

extern xtn_crypt_t xtn_crypt;
extern xtn_cmp_t xtn_cmp;

struct xtn_module_t {
  char *xtn_text;
  int (*xtn_init)(void);
  xtn_cmp_t xtn_check;
  xtn_crypt_t xtn_function;
};

extern struct xtn_module_t xtn_all[];

#endif
