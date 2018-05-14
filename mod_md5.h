/* 
   Standard MD5 implementation

   Copyright (C) Lepton (lepton@runbox.com)
*/

#include "xtn_def.h"

int xtn_md5_init(void);
int xtn_md5_cmp(CODE_BLOCK_PTR h0, CODE_BLOCK_PTR h1);
CODE_BLOCK_PTR xtn_md5_crypt(char *passwd, int len, BYTE *CMAP);
