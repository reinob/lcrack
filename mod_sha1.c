/* 
   Standard SHA-1 implementation  
*/

#include "xtn_method.h"

#include <stdio.h>
#include <string.h>
#include "sha1.h"

int xtn_sha1_init(void) {
  fprintf(stderr, "xtn: initialized 'sha1' module\n");
  
  return 20;
}

int xtn_sha1_cmp(CODE_BLOCK_PTR h0, CODE_BLOCK_PTR h1) {
  return !memcmp(h0, h1, 20 * sizeof(BYTE));
}

CODE_BLOCK_PTR xtn_sha1_crypt(char *passwd, int len, BYTE *CMAP) {
  static BYTE sha1_buf[20];
  BYTE pwd_buf[20];
  int j;

  SHA1Context sha;

  for(j = 0; j < len; j ++)
    pwd_buf[j] = CMAP[(int)passwd[j]];
  
  SHA1Reset(&sha);
  SHA1Input(&sha, (const unsigned char *) pwd_buf, len);
  SHA1Result(&sha, sha1_buf);
  
  return sha1_buf;
}
