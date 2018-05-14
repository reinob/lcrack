/* 
   Standard SHA-1 implementation
*/

#include "xtn_def.h"

int xtn_sha1_init(void);
int xtn_sha1_cmp(CODE_BLOCK_PTR h0, CODE_BLOCK_PTR h1);
CODE_BLOCK_PTR xtn_sha1_crypt(char *passwd, int len, BYTE *CMAP);
