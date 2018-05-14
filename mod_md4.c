/* 
   Standard MD4 implementation

   Copyright (C) Lepton (lepton@runbox.com)
*/

#include "xtn_method.h"

#include <stdio.h>
#include <string.h>

extern void mdfour(unsigned char *out, unsigned char *in, int n);

int xtn_md4_init(void) {
  fprintf(stderr, "xtn: initialized 'md4' module\n");
  return 16;
}

int xtn_md4_cmp(CODE_BLOCK_PTR h0, CODE_BLOCK_PTR h1) {
  return !memcmp(h0, h1, 16 * sizeof(BYTE));
}

CODE_BLOCK_PTR xtn_md4_crypt(char *passwd, int len, BYTE *CMAP) {
  static BYTE md4_buf[16];
  BYTE pwd_buf[16];
  int j;

  for(j = 0; j < len; j ++)
    pwd_buf[j] = CMAP[(int)passwd[j]];

  mdfour(md4_buf, pwd_buf, len);

  return md4_buf;
}
