/* 
   Null module implementation

   Copyright (C) Lepton (lepton@runbox.com)
*/

#include "xtn_method.h"

#include <stdio.h>
#include <string.h>

int xtn_null_init(void) {
  fprintf(stderr, "xtn: initialized 'null' module\n");
  return 1;
}

int xtn_null_cmp(CODE_BLOCK_PTR h0, CODE_BLOCK_PTR h1) {
  return (h0[0] == h1[0]);
}

CODE_BLOCK_PTR xtn_null_crypt(char *passwd, int len, BYTE *CMAP) {
  static BYTE buf[1];
  int j;

  for(buf[0] = 0xee, j = 0; j < len; j ++) {
    buf[0] ^= CMAP[(int)passwd[j]];
  }

  return buf;
}
