/* 
   Standard MD5 implementation

   Copyright (C) Lepton (lepton@runbox.com)
*/

#include "xtn_method.h"

#include <stdio.h>
#include <string.h>

extern void md5(unsigned char *digest, unsigned char *passwd, int len);

int xtn_md5_init(void) {
  fprintf(stderr, "xtn: initialized 'md5' module\n");
  return 16;
}

int xtn_md5_cmp(CODE_BLOCK_PTR h0, CODE_BLOCK_PTR h1) {
  return !memcmp(h0, h1, 16 * sizeof(BYTE));
}

CODE_BLOCK_PTR xtn_md5_crypt(char *passwd, int len, BYTE *CMAP) {
  static BYTE md5_buf[16];
  BYTE pwd_buf[16];
  int j;

  for(j = 0; j < len; j ++)
    pwd_buf[j] = CMAP[(int)passwd[j]];


  md5(md5_buf, pwd_buf, len);

  return md5_buf;
}
