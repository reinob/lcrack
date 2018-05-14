/* 
   Lotus HTTP Password Hash implementation

   Copyright (C) Bernardo Reino (lepton@runbox.com), 
             and Miguel Dilaj (nekromancer@eudoramail.com)

   Based on code by Jeff Fay (jeff@sdii.com)
*/

#include "xtn_def.h"

int xtn_dom_init(void);
int xtn_dom_cmp(CODE_BLOCK_PTR h0, CODE_BLOCK_PTR h1);
CODE_BLOCK_PTR xtn_dom_crypt(char *passwd, int len, BYTE *CMAP);
