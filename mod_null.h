/* 
   Null module

   Copyright (C) Lepton (lepton@runbox.com)
*/

#include "xtn_def.h"

int xtn_null_init(void);
int xtn_null_cmp(CODE_BLOCK_PTR h0, CODE_BLOCK_PTR h1);
CODE_BLOCK_PTR xtn_null_crypt(char *passwd, int len, BYTE *CMAP);
