/* 
   NT (Unicode) MD4 implementation

   Copyright (C) Lepton (lepton@runbox.com)
*/

#include "xtn_method.h"

#include <stdio.h>
#include <string.h>

extern void mdfour(unsigned char *out, unsigned char *in, int len);

int xtn_nt4_init(void) {
  fprintf(stderr, "xtn: initialized 'NT md4/unicode' module\n");
  return 16;
}

int xtn_nt4_cmp(CODE_BLOCK_PTR h0, CODE_BLOCK_PTR h1) {
  return !memcmp(h0, h1, 16 * sizeof(BYTE));
}

CODE_BLOCK_PTR xtn_nt4_crypt(char *passwd, int len, BYTE *CMAP) {
  static BYTE md4_buf[16];
  BYTE aux[64];
  int j;

  for(j = 0; j < len; j ++) {
    aux[2*j] = CMAP[(int)passwd[j]];
    aux[2*j+1] = '\0';
  }

  len *= 2;
  mdfour(md4_buf, aux, len);

  return md4_buf;
}
