/* 
   NT (unicode) MD4 implementation

   Copyright (C) Lepton (lepton@runbox.com)
*/

#include "xtn_def.h"

int xtn_nt4_init(void);
int xtn_nt4_cmp(CODE_BLOCK_PTR h0, CODE_BLOCK_PTR h1);
CODE_BLOCK_PTR xtn_nt4_crypt(char *passwd, int len, BYTE *CMAP);
