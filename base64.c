#include <stdlib.h>

/*
 * Quick & dirty base64 handling stuff. Currently not used by any
 * of the modules, but provided if needed.
 *
 * NOTE: Not tested, seems to work, but might not handle weird
 * situations, so use only if you're really lazy to do it yourself :)
 *
 * Bernardo Reino (aka Lepton)
 * 20021120
 *
 */

char tbl64[] = 
  "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
  "abcdefghijklmnopqrstuvwxyz"
  "0123456789+/";

int idx64(unsigned char x) {
  int i;

  if(x == '=')
    return 0;

  for(i = 0; i < sizeof(tbl64); i ++)
    if(tbl64[i] == x)
      return i;

  return 0xff;
}

char *base64_encode(unsigned char *s_in, unsigned long s_len) {
  unsigned long g24;
  unsigned long buf_len;
  unsigned char *buf64, *ptr64;

  buf_len = (4 * (s_len + 2)/3) + 1;
  ptr64 = buf64 = calloc(1, buf_len);

  while(s_len > 2) {
    g24 = (s_in[0] << 16) + (s_in[1] << 8) + s_in[2];

    ptr64[0] = tbl64[(g24 >> 18) & 0x3f];
    ptr64[1] = tbl64[(g24 >> 12) & 0x3f];
    ptr64[2] = tbl64[(g24 >> 6) & 0x3f];
    ptr64[3] = tbl64[(g24 & 0x3f)];

    ptr64 += 4;
    s_in += 3;
    s_len -= 3;
  }

  switch(s_len) {
  case 2:
    g24 = (s_in[0] << 16) + (s_in[1] << 8);

    ptr64[0] = tbl64[(g24 >> 18) & 0x3f];
    ptr64[1] = tbl64[(g24 >> 12) & 0x3f];
    ptr64[2] = tbl64[(g24 >> 6) & 0x3f];
    ptr64[3] = '=';
    
    ptr64 += 4;
    break;

  case 1:
    g24 = (s_in[0] << 16);

    ptr64[0] = tbl64[(g24 >> 18) & 0x3f];
    ptr64[1] = tbl64[(g24 >> 12) & 0x3f];
    ptr64[2] = '=';
    ptr64[3] = '=';
    
    ptr64 += 4;
    break;
  }

  *ptr64 = '\0';
  return (char *)buf64;
}

char *base64_decode(char *s_in, int s_len, int *o_len) {
  unsigned int c0, c1, c2, c3;
  unsigned char *buf8, *ptr8, *s_idx;

  s_idx = calloc(1, s_len + 1);

  for(c0 = 0; c0 < s_len; c0 ++) {
    if((s_idx[c0] = idx64(s_in[c0])) == 0xff)
      return NULL;
  }

  *o_len = (s_len/4) * 3 + 1;
  ptr8 = buf8 = calloc(1, *o_len);

  while(s_len >= 4) {
    c0 = s_idx[0];
    c1 = s_idx[1];
    c2 = s_idx[2];
    c3 = s_idx[3];

    ptr8[0] = (c0 << 2) | (c1 >> 4);
    ptr8[1] = ((c1 & 0x0f) << 4) | (c2 >> 2);
    ptr8[2] = ((c2 & 0x3) << 6) | c3;

    ptr8 += 3;
    s_in += 4;
    s_len -= 4;
  }

  *ptr8 = '\0';
  free(s_idx);
  return (char *)buf8;
}
